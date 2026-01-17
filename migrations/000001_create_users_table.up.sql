CREATE TABLE IF NOT EXISTS users (
    id uuid primary key default gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active bool default true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
create index idx_users_active on users(is_active)
where is_active = true;
create table audit_logs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid null,
    event_type text not null,
    ip inet,
    ua text,
    payload jsonb,
    created_at timestamptz default now()
);
create index idx_audit_user_id on audit_logs(user_id);
create index idx_audit_created on audit_logs(created_at desc);
create index idx_audit_event_type on audit_logs(event_type);