package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/repository/postgres/sqlc"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type UserRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *UserRepository) Create(user *domain.User) error {
	ctx := context.Background()

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := r.queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:           uuidToPgtype(user.ID),
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		CreatedAt:    timeToPgtype(now),
		UpdatedAt:    timeToPgtype(now),
	})
	return err
}

func (r *UserRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	ctx := context.Background()

	dbUser, err := r.queries.GetUserByID(ctx, uuidToPgtype(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return r.toDomain(dbUser), nil
}

func (r *UserRepository) GetByEmail(email string) (*domain.User, error) {
	ctx := context.Background()

	dbUser, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return r.toDomain(dbUser), nil
}

func (r *UserRepository) Update(user *domain.User) error {
	ctx := context.Background()
	now := time.Now()
	user.UpdatedAt = now

	_, err := r.queries.UpdateUser(ctx, sqlc.UpdateUserParams{
		ID:           uuidToPgtype(user.ID),
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		UpdatedAt:    timeToPgtype(now),
	})
	return err
}

func (r *UserRepository) Delete(id uuid.UUID) error {
	ctx := context.Background()
	return r.queries.DeleteUser(ctx, uuidToPgtype(id))
}

func (r *UserRepository) toDomain(dbUser sqlc.User) *domain.User {
	user := &domain.User{
		ID:           pgtypeToUUID(dbUser.ID),
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
	}
	if dbUser.CreatedAt.Valid {
		user.CreatedAt = dbUser.CreatedAt.Time
	}
	if dbUser.UpdatedAt.Valid {
		user.UpdatedAt = dbUser.UpdatedAt.Time
	}
	return user
}

func uuidToPgtype(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}

func pgtypeToUUID(id pgtype.UUID) uuid.UUID {
	return uuid.UUID(id.Bytes)
}

func timeToPgtype(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  t,
		Valid: true,
	}
}
