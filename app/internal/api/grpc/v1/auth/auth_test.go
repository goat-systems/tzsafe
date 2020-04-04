package auth

import (
	"context"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func Test_Authenticate(t *testing.T) {
	type input struct {
		users    map[string]string
		username string
		password string
	}

	type want struct {
		err           bool
		errContains   string
		usernameClaim string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			"is successful",
			input{
				map[string]string{
					"user1": "passwd",
					"user2": "otherpasswd",
				},
				"user1",
				"passwd",
			},
			want{
				false,
				"",
				"user1",
			},
		},
		{
			"handles failure to authenticate",
			input{
				map[string]string{
					"user1": "passwd",
					"user2": "otherpasswd",
				},
				"user1",
				"wrongpasswd",
			},
			want{
				true,
				"failed to authenticate",
				"",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer("secret", tt.input.users)
			authResp, err := server.Authenticate(context.Background(), &AuthenticateInput{
				Username: tt.input.username,
				Password: tt.input.password,
			})

			if tt.want.err {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.want.errContains)
			} else {
				assert.Nil(t, err)
				claims := jwt.MapClaims{}
				_, err = jwt.ParseWithClaims(authResp.Token, claims, func(token *jwt.Token) (interface{}, error) {
					return []byte("secret"), nil
				})

				usernameClaim := claims["username"]
				assert.Nil(t, err)
				assert.Equal(t, tt.want.usernameClaim, usernameClaim)
			}
		})
	}
}

func Test_Refresh(t *testing.T) {
	type input struct {
		users         map[string]string
		username      string
		password      string
		tokenLifespan time.Duration
		sleep         time.Duration
	}

	type want struct {
		err           bool
		errContains   string
		usernameClaim string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			"is successful",
			input{
				map[string]string{
					"user1": "passwd",
					"user2": "otherpasswd",
				},
				"user1",
				"passwd",
				1 * time.Minute,
				0,
			},
			want{
				false,
				"",
				"user1",
			},
		},
		{
			"handles failure to authenticate",
			input{
				map[string]string{
					"user1": "passwd",
					"user2": "otherpasswd",
				},
				"user1",
				"passwd",
				1 * time.Millisecond,
				3 * time.Millisecond,
			},
			want{
				true,
				"",
				"",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer("secret", tt.input.users)
			tokenLifespan = tt.input.tokenLifespan

			authResp, err := server.Authenticate(context.Background(), &AuthenticateInput{
				Username: tt.input.username,
				Password: tt.input.password,
			})
			assert.Nil(t, err)

			// expire the token if need be
			time.Sleep(tt.input.sleep)

			refreshResp, err := server.Refresh(context.Background(), &RefreshInput{
				Token: authResp.Token,
			})
			if tt.want.err {
				assert.NotNil(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tt.want.errContains)
				}
			} else {
				assert.Nil(t, err)
				claims := jwt.MapClaims{}
				_, err = jwt.ParseWithClaims(refreshResp.Token, claims, func(token *jwt.Token) (interface{}, error) {
					return []byte("secret"), nil
				})

				usernameClaim := claims["username"]
				assert.Nil(t, err)
				assert.Equal(t, tt.want.usernameClaim, usernameClaim)
			}
		})
	}
}
