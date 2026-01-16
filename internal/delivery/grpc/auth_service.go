package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/yourusername/authservice/api/proto/auth"
	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/usecase/auth/login"
	"github.com/yourusername/authservice/internal/usecase/auth/logout"
	"github.com/yourusername/authservice/internal/usecase/auth/refresh"
	"github.com/yourusername/authservice/internal/usecase/auth/register"
)

type AuthServiceParams struct {
	UserRepo    domain.UserRepository
	TokenRepo   domain.TokenRepository
	SessionRepo domain.SessionRepository
	Hasher      hasher.Hasher
	JWT         jwt.Manager
	SessionExp  time.Duration
}

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	*AuthServiceParams
}

func NewAuthServiceServer(params *AuthServiceParams) *AuthServiceServer {
	return &AuthServiceServer{
		AuthServiceParams: params,
	}
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	result, err := register.New(ctx,
		&register.Params{
			UserRepo:  s.UserRepo,
			TokenRepo: s.TokenRepo,
			Hasher:    s.Hasher,
			JWT:       s.JWT,
		},
		&register.Payload{
			Email:    req.Email,
			Password: req.Password,
		},
	).Execute()

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

	result, err := login.New(ctx,
		&login.Params{
			UserRepo:    s.UserRepo,
			TokenRepo:   s.TokenRepo,
			SessionRepo: s.SessionRepo,
			Hasher:      s.Hasher,
			JWT:         s.JWT,
			SessionExp:  s.SessionExp,
		},
		&login.Payload{
			Email:     req.Email,
			Password:  req.Password,
			UserAgent: req.UserAgent,
			IP:        req.Ip,
		},
	).Execute()

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

	result, err := refresh.New(ctx,
		&refresh.Params{
			UserRepo:  s.UserRepo,
			TokenRepo: s.TokenRepo,
			JWT:       s.JWT,
		},
		&refresh.Payload{
			RefreshToken: req.RefreshToken,
		},
	).Execute()

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.TokenResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
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

	if err := logout.New(ctx,
		&logout.Params{
			SessionRepo: s.SessionRepo,
			TokenRepo:   s.TokenRepo,
		},
		&logout.Payload{
			UserID:    userID,
			SessionID: req.SessionId,
		},
	).Execute(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.LogoutResponse{Success: true}, nil
}

func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	claims, err := s.JWT.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID.String(),
		Email:  claims.Email,
	}, nil
}
