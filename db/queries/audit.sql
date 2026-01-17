-- name: CreateAuditLog :one
INSERT INTO audit_logs (user_id, event_type, ip, ua, payload)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAuditLogsByUserID :many
SELECT * FROM audit_logs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: DeleteOldAuditLogs :exec
DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '14 days';
