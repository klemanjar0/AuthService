package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yourusername/authservice/internal/config"
	grpcdelivery "github.com/yourusername/authservice/internal/delivery/grpc"
	httpdelivery "github.com/yourusername/authservice/internal/delivery/http"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/pkg/logger"
	postgresrepo "github.com/yourusername/authservice/internal/repository/postgres"
	redisrepo "github.com/yourusername/authservice/internal/repository/redis"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger.Init(cfg.Server.Env)
	log := logger.Get()

	log.Info().Msg("starting auth service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.Database.DSN())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping database")
	}
	log.Info().Msg("connected to database")

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr(),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal().Err(err).Msg("failed to connect to redis")
	}
	log.Info().Msg("connected to redis")

	userRepo := postgresrepo.NewUserRepository(pool)
	tokenRepo := redisrepo.NewTokenRepository(rdb)
	sessionRepo := redisrepo.NewSessionRepository(rdb)

	passwordHasher := hasher.NewBcryptHasher(0)
	jwtManager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)

	router := httpdelivery.NewRouter(&httpdelivery.RouterParams{
		UserRepo:    userRepo,
		TokenRepo:   tokenRepo,
		SessionRepo: sessionRepo,
		Hasher:      passwordHasher,
		JWT:         jwtManager,
		SessionExp:  cfg.Session.Expiry,
	})
	router.Setup()

	grpcServer := grpcdelivery.NewServer(&grpcdelivery.AuthServiceParams{
		UserRepo:    userRepo,
		TokenRepo:   tokenRepo,
		SessionRepo: sessionRepo,
		Hasher:      passwordHasher,
		JWT:         jwtManager,
		SessionExp:  cfg.Session.Expiry,
	})

	errChan := make(chan error, 2)

	go func() {
		addr := ":" + cfg.Server.HTTPPort
		log.Info().Str("addr", addr).Msg("starting HTTP server")
		if err := router.App().Listen(addr); err != nil {
			errChan <- fmt.Errorf("http server error: %w", err)
		}
	}()

	go func() {
		addr := ":" + cfg.Server.GRPCPort
		log.Info().Str("addr", addr).Msg("starting gRPC server")
		if err := grpcServer.Start(addr); err != nil {
			errChan <- fmt.Errorf("grpc server error: %w", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Error().Err(err).Msg("server error")
	case sig := <-quit:
		log.Info().Str("signal", sig.String()).Msg("shutting down")
	}

	log.Info().Msg("stopping servers")
	grpcServer.Stop()
	if err := router.App().Shutdown(); err != nil {
		log.Error().Err(err).Msg("error shutting down HTTP server")
	}

	log.Info().Msg("auth service stopped")
}
