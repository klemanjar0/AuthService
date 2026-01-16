package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/usecase/auth"
)

type AuthHandler struct {
	authUC auth.UseCase
}

func NewAuthHandler(authUC auth.UseCase) *AuthHandler {
	return &AuthHandler{authUC: authUC}
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AuthResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	SessionID    string       `json:"session_id,omitempty"`
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "email and password are required",
		})
	}

	result, err := h.authUC.Register(c.Context(), auth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(AuthResponse{
		User: UserResponse{
			ID:    result.User.ID.String(),
			Email: result.User.Email,
		},
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
	})
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "email and password are required",
		})
	}

	result, err := h.authUC.Login(c.Context(), auth.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: c.Get("User-Agent"),
		IP:        c.IP(),
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    result.SessionID,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	})

	return c.JSON(AuthResponse{
		User: UserResponse{
			ID:    result.User.ID.String(),
			Email: result.User.Email,
		},
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		SessionID:    result.SessionID,
	})
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	if req.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "refresh_token is required",
		})
	}

	tokens, err := h.authUC.Refresh(c.Context(), auth.RefreshInput{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	sessionID := c.Cookies("session_id")

	if err := h.authUC.Logout(c.Context(), userID, sessionID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    "",
		HTTPOnly: true,
		MaxAge:   -1,
	})

	return c.JSON(fiber.Map{
		"message": "logged out successfully",
	})
}

func (h *AuthHandler) Me(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	email, _ := c.Locals("email").(string)

	return c.JSON(UserResponse{
		ID:    userID.String(),
		Email: email,
	})
}
