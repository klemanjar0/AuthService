package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/yourusername/authservice/internal/pkg/jwt"
)

type AuthMiddleware struct {
	jwtManager jwt.Manager
}

func NewAuthMiddleware(jwtManager jwt.Manager) *AuthMiddleware {
	return &AuthMiddleware{jwtManager: jwtManager}
}

func (m *AuthMiddleware) JWT() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization header format",
			})
		}

		claims, err := m.jwtManager.ValidateAccessToken(parts[1])
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)

		return c.Next()
	}
}

func (m *AuthMiddleware) Session(sessionValidator func(sessionID string) error) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessionID := c.Cookies("session_id")
		if sessionID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing session",
			})
		}

		if err := sessionValidator(sessionID); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired session",
			})
		}

		c.Locals("session_id", sessionID)

		return c.Next()
	}
}
