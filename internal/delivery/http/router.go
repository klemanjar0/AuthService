package http

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/yourusername/authservice/internal/delivery/http/handler"
	"github.com/yourusername/authservice/internal/delivery/http/middleware"
	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
)

type RouterParams struct {
	UserRepo    domain.UserRepository
	TokenRepo   domain.TokenRepository
	SessionRepo domain.SessionRepository
	Hasher      hasher.Hasher
	JWT         jwt.Manager
	SessionExp  time.Duration
}

type Router struct {
	app         *fiber.App
	authHandler *handler.AuthHandler
	authMW      *middleware.AuthMiddleware
}

func NewRouter(params *RouterParams) *Router {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	authHandler := handler.NewAuthHandler(&handler.AuthHandlerParams{
		UserRepo:    params.UserRepo,
		TokenRepo:   params.TokenRepo,
		SessionRepo: params.SessionRepo,
		Hasher:      params.Hasher,
		JWT:         params.JWT,
		SessionExp:  params.SessionExp,
	})
	authMW := middleware.NewAuthMiddleware(params.JWT)

	return &Router{
		app:         app,
		authHandler: authHandler,
		authMW:      authMW,
	}
}

func (r *Router) Setup() {
	api := r.app.Group("/api")
	v1 := api.Group("/v1")

	auth := v1.Group("/auth")
	auth.Post("/register", r.authHandler.Register)
	auth.Post("/login", r.authHandler.Login)
	auth.Post("/refresh", r.authHandler.Refresh)
	auth.Post("/refresh-session", r.authHandler.RefreshSession)
	auth.Post("/logout", r.authMW.JWT(), r.authHandler.Logout)
	auth.Post("/logout-all", r.authMW.JWT(), r.authHandler.LogoutAll)

	user := v1.Group("/user")
	user.Use(r.authMW.JWT())
	user.Get("/me", r.authHandler.Me)

	r.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
}

func (r *Router) App() *fiber.App {
	return r.app
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error": err.Error(),
	})
}
