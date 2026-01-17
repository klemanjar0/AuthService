package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/usecase/auth/login"
	"github.com/yourusername/authservice/internal/usecase/auth/logout"
	"github.com/yourusername/authservice/internal/usecase/auth/logoutall"
	"github.com/yourusername/authservice/internal/usecase/auth/refresh"
	"github.com/yourusername/authservice/internal/usecase/auth/refreshsession"
	"github.com/yourusername/authservice/internal/usecase/auth/register"
	"github.com/yourusername/authservice/internal/usecase/user/getbyid"
)

type AuthHandlerParams struct {
	UserRepo    domain.UserRepository
	TokenRepo   domain.TokenRepository
	SessionRepo domain.SessionRepository
	AuditRepo   domain.AuditLogRepository
	Hasher      hasher.Hasher
	JWT         jwt.Manager
	SessionExp  time.Duration
}

type AuthHandler struct {
	*AuthHandlerParams
}

func NewAuthHandler(params *AuthHandlerParams) *AuthHandler {
	return &AuthHandler{AuthHandlerParams: params}
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

type SessionResponse struct {
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
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

	result, err := register.New(c.Context(),
		&register.Params{
			UserRepo:  h.UserRepo,
			TokenRepo: h.TokenRepo,
			AuditRepo: h.AuditRepo,
			Hasher:    h.Hasher,
			JWT:       h.JWT,
		},
		&register.Payload{
			Email:    req.Email,
			Password: req.Password,
		},
	).Execute()

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

	result, err := login.New(c.Context(),
		&login.Params{
			UserRepo:    h.UserRepo,
			TokenRepo:   h.TokenRepo,
			SessionRepo: h.SessionRepo,
			AuditRepo:   h.AuditRepo,
			Hasher:      h.Hasher,
			JWT:         h.JWT,
			SessionExp:  h.SessionExp,
		},
		&login.Payload{
			Email:     req.Email,
			Password:  req.Password,
			UserAgent: c.Get("User-Agent"),
			IP:        c.IP(),
		},
	).Execute()

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

	result, err := refresh.New(c.Context(),
		&refresh.Params{
			UserRepo:  h.UserRepo,
			TokenRepo: h.TokenRepo,
			AuditRepo: h.AuditRepo,
			JWT:       h.JWT,
		},
		&refresh.Payload{
			RefreshToken: req.RefreshToken,
		},
	).Execute()

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(TokenResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
	})
}

func (h *AuthHandler) RefreshSession(c *fiber.Ctx) error {
	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "session_id cookie is required",
		})
	}

	result, err := refreshsession.New(c.Context(),
		&refreshsession.Params{
			SessionRepo: h.SessionRepo,
			SessionExp:  h.SessionExp,
		},
		&refreshsession.Payload{
			SessionID: sessionID,
		},
	).Execute()

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    result.Session.ID,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	})

	return c.JSON(SessionResponse{
		SessionID: result.Session.ID,
		ExpiresAt: result.Session.ExpiresAt.Format(time.RFC3339),
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

	var refreshToken string
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&body); err == nil {
		refreshToken = body.RefreshToken
	}

	if err := logout.New(c.Context(),
		&logout.Params{
			SessionRepo: h.SessionRepo,
			TokenRepo:   h.TokenRepo,
			AuditRepo:   h.AuditRepo,
		},
		&logout.Payload{
			UserID:       userID,
			SessionID:    sessionID,
			RefreshToken: refreshToken,
		},
	).Execute(); err != nil {
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

func (h *AuthHandler) LogoutAll(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	if err := logoutall.New(c.Context(),
		&logoutall.Params{
			SessionRepo: h.SessionRepo,
			TokenRepo:   h.TokenRepo,
		},
		&logoutall.Payload{
			UserID: userID,
		},
	).Execute(); err != nil {
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
		"message": "logged out from all devices",
	})
}

func (h *AuthHandler) Me(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	result, err := getbyid.New(c.Context(),
		&getbyid.Params{
			UserRepo: h.UserRepo,
		},
		&getbyid.Payload{
			UserID: userID,
		},
	).Execute()

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(UserResponse{
		ID:    result.User.ID.String(),
		Email: result.User.Email,
	})
}
