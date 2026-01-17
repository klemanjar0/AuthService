package postgres

import (
	"context"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/repository/postgres/sqlc"
)

type AuditLogRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

func NewAuditLogRepository(pool *pgxpool.Pool) *AuditLogRepository {
	return &AuditLogRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *AuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	var userID pgtype.UUID
	if log.UserID != nil {
		userID = uuidToPgtype(*log.UserID)
	}

	var ip *netip.Addr
	if log.IP != "" {
		parsed, err := netip.ParseAddr(log.IP)
		if err == nil {
			ip = &parsed
		}
	}

	var ua pgtype.Text
	if log.UA != "" {
		ua = pgtype.Text{String: log.UA, Valid: true}
	}

	_, err := r.queries.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		UserID:    userID,
		EventType: log.EventType,
		Ip:        ip,
		Ua:        ua,
		Payload:   log.Payload,
	})
	return err
}

func (r *AuditLogRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*domain.AuditLog, error) {
	logs, err := r.queries.GetAuditLogsByUserID(ctx, sqlc.GetAuditLogsByUserIDParams{
		UserID: uuidToPgtype(userID),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}

	result := make([]*domain.AuditLog, len(logs))
	for i, log := range logs {
		result[i] = r.toDomain(log)
	}
	return result, nil
}

func (r *AuditLogRepository) DeleteOld(ctx context.Context) error {
	return r.queries.DeleteOldAuditLogs(ctx)
}

func (r *AuditLogRepository) toDomain(dbLog sqlc.AuditLog) *domain.AuditLog {
	log := &domain.AuditLog{
		ID:        pgtypeToUUID(dbLog.ID),
		EventType: dbLog.EventType,
		Payload:   dbLog.Payload,
	}

	if dbLog.UserID.Valid {
		id := pgtypeToUUID(dbLog.UserID)
		log.UserID = &id
	}

	if dbLog.Ip != nil {
		log.IP = dbLog.Ip.String()
	}

	if dbLog.Ua.Valid {
		log.UA = dbLog.Ua.String
	}

	if dbLog.CreatedAt.Valid {
		log.CreatedAt = dbLog.CreatedAt.Time
	}

	return log
}
