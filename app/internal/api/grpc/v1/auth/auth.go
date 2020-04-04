package auth

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	tokenLifespan = time.Minute * 10
)

// Server -
type Server struct {
	users  map[string]string
	secret []byte
}

// Claims -
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// NewServer -
func NewServer(secret string, users map[string]string) *Server {
	return &Server{
		users:  users,
		secret: []byte(secret),
	}
}

// Authenticate -
func (s *Server) Authenticate(ctx context.Context, input *AuthenticateInput) (*AuthenticateResponse, error) {
	expectedPassword, ok := s.users[input.Username]
	if !ok || expectedPassword != input.Password {
		return &AuthenticateResponse{}, status.Error(codes.Unauthenticated, "failed to authenticate")
	}

	expirationTime := time.Now().Add(tokenLifespan)
	claims := &Claims{
		Username: input.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return &AuthenticateResponse{}, status.Errorf(codes.Internal, "failed to authenticate: failed to sign jwt: %v", err.Error())
	}

	return &AuthenticateResponse{
		Token: tokenString,
	}, nil
}

// Refresh -
func (s *Server) Refresh(ctx context.Context, input *RefreshInput) (*RefreshResponse, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(input.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return &RefreshResponse{}, status.Errorf(codes.Unauthenticated, "failed to authenticate: %v", err.Error())
		}
		return &RefreshResponse{}, status.Errorf(codes.Internal, "failed to parse claims: %v", err.Error())
	}

	if !tkn.Valid {
		return &RefreshResponse{}, status.Errorf(codes.Unauthenticated, "failed to authenticate: %v", err.Error())
	}

	claims.ExpiresAt = time.Now().Add(tokenLifespan).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return &RefreshResponse{}, status.Errorf(codes.Internal, "failed to sign token: %v", err.Error())
	}

	return &RefreshResponse{
		Token: tokenString,
	}, nil
}
