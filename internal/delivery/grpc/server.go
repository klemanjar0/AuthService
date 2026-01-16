package grpc

import (
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/yourusername/authservice/api/proto/auth"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	authUC "github.com/yourusername/authservice/internal/usecase/auth"
)

type Server struct {
	grpcServer  *grpc.Server
	authService *AuthServiceServer
}

func NewServer(authUseCase authUC.UseCase, jwtManager jwt.Manager) *Server {
	grpcServer := grpc.NewServer()

	authService := NewAuthServiceServer(authUseCase, jwtManager)
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
