package endorsing

import (
	context "context"

	gotezos "github.com/goat-systems/go-tezos/v2"
	"github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
)

type Server struct {
	logger *logrus.Logger
	gt     *gotezos.Iface
}

func NewServer(gt gotezos.Iface, logger *logrus.Logger) *Server {
	return &Server{
		logger: logger,
		gt:     gt,
	}
}

func (s *Server) Endorse(ctx context.Context, in *Endorsement, opts ...grpc.CallOption) (*EndorsementResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"client":    "",
		"blockhash": in.Block,
	}).Info("Received endorsement.")

	return &EndorsementResponse{}, nil
}

func (s *Server) EndorseStream(ctx context.Context, in *Subscribe, opts ...grpc.CallOption) (V1_EndorseStreamClient, error) {
	return nil, nil
}
