package grpc

import (
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/yourusername/authservice/api/proto/auth"
)

type Server struct {
	grpcServer  *grpc.Server
	authService *AuthServiceServer
}

func NewServer(params *AuthServiceParams) *Server {
	grpcServer := grpc.NewServer()

	authService := NewAuthServiceServer(params)
	pb.RegisterAuthServiceServer(grpcServer, authService)

	reflection.Register(grpcServer)

	return &Server{
		grpcServer:  grpcServer,
		authService: authService,
	}
}

func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.grpcServer.Serve(lis)
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
