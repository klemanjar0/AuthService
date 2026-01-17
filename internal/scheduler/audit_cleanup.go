package scheduler

import (
	"context"
	"time"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

type AuditCleanupScheduler struct {
	auditRepo domain.AuditLogRepository
	interval  time.Duration
	stopCh    chan struct{}
}

func NewAuditCleanupScheduler(auditRepo domain.AuditLogRepository, interval time.Duration) *AuditCleanupScheduler {
	return &AuditCleanupScheduler{
		auditRepo: auditRepo,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
}

func (s *AuditCleanupScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	logger.Info().Dur("interval", s.interval).Msg("audit cleanup scheduler started")

	s.cleanup(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("audit cleanup scheduler stopped by context")
			return
		case <-s.stopCh:
			logger.Info().Msg("audit cleanup scheduler stopped")
			return
		case <-ticker.C:
			s.cleanup(ctx)
		}
	}
}

func (s *AuditCleanupScheduler) Stop() {
	close(s.stopCh)
}

func (s *AuditCleanupScheduler) cleanup(ctx context.Context) {
	if err := s.auditRepo.DeleteOld(ctx); err != nil {
		logger.Error().Err(err).Msg("failed to cleanup old audit logs")
		return
	}
	logger.Debug().Msg("old audit logs cleaned up successfully")
}
