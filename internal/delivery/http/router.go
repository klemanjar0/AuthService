package http

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/yourusername/authservice/internal/delivery/http/handler"
	"github.com/yourusername/authservice/internal/delivery/http/middleware"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	authUC "github.com/yourusername/authservice/internal/usecase/auth"
	userUC "github.com/yourusername/authservice/internal/usecase/user"
)

type Router struct {
	app         *fiber.App
	authHandler *handler.AuthHandler
	authMW      *middleware.AuthMiddleware
}

func NewRouter(
	authUseCase authUC.UseCase,
	userUseCase userUC.UseCase,
	jwtManager jwt.Manager,
) *Router {
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

	authHandler := handler.NewAuthHandler(authUseCase)
	authMW := middleware.NewAuthMiddleware(jwtManager)

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
	auth.Post("/logout", r.authMW.JWT(), r.authHandler.Logout)

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
