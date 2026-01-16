package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/yourusername/authservice/api/proto/auth"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	authUC "github.com/yourusername/authservice/internal/usecase/auth"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	authUC     authUC.UseCase
	jwtManager jwt.Manager
}

func NewAuthServiceServer(authUseCase authUC.UseCase, jwtManager jwt.Manager) *AuthServiceServer {
	return &AuthServiceServer{
		authUC:     authUseCase,
		jwtManager: jwtManager,
	}
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	result, err := s.authUC.Register(ctx, authUC.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.AuthResponse{
		User: &pb.User{
			Id:    result.User.ID.String(),
			Email: result.User.Email,
		},
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
	}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	result, err := s.authUC.Login(ctx, authUC.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: req.UserAgent,
		IP:        req.Ip,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.AuthResponse{
		User: &pb.User{
			Id:    result.User.ID.String(),
			Email: result.User.Email,
		},
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		SessionId:    result.SessionID,
	}, nil
}

func (s *AuthServiceServer) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	tokens, err := s.authUC.Refresh(ctx, authUC.RefreshInput{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *AuthServiceServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	userID, err := parseUUID(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	if err := s.authUC.Logout(ctx, userID, req.SessionId); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.LogoutResponse{Success: true}, nil
}

func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	claims, err := s.jwtManager.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID.String(),
		Email:  claims.Email,
	}, nil
}
