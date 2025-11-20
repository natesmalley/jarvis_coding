-- Initialize PostgreSQL for Jarvis Session Manager
-- This script sets up the database schema for session management

-- Create sessions table for tracking active sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'creating',
    frontend_container_id VARCHAR(255),
    backend_container_id VARCHAR(255),
    frontend_port INTEGER,
    backend_port INTEGER,
    frontend_url VARCHAR(512),
    backend_url VARCHAR(512),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP,
    terminated_at TIMESTAMP,
    metadata JSONB DEFAULT '{}',
    CONSTRAINT idx_session_id_unique UNIQUE (session_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_session_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_session_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_session_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_session_created_at ON sessions(created_at);

-- Create session_events table for audit logging
CREATE TABLE IF NOT EXISTS session_events (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create indexes for session_events
CREATE INDEX IF NOT EXISTS idx_session_events_session_id ON session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_session_events_created_at ON session_events(created_at);
CREATE INDEX IF NOT EXISTS idx_session_events_type ON session_events(event_type);

-- Create function to automatically clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    UPDATE sessions 
    SET status = 'expired', 
        terminated_at = NOW()
    WHERE expires_at < NOW() 
    AND status IN ('creating', 'active')
    AND terminated_at IS NULL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup event
    IF deleted_count > 0 THEN
        INSERT INTO session_events (session_id, event_type, details)
        SELECT session_id, 'auto_cleanup', 
               jsonb_build_object('reason', 'expired', 'count', deleted_count)
        FROM sessions 
        WHERE status = 'expired' 
        AND terminated_at >= NOW() - INTERVAL '1 minute';
    END IF;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to create session-specific schema
CREATE OR REPLACE FUNCTION create_session_schema(session_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Create schema for session
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', 'session_' || session_name);
    
    -- Grant permissions
    EXECUTE format('GRANT ALL ON SCHEMA %I TO postgres', 'session_' || session_name);
END;
$$ LANGUAGE plpgsql;

-- Create function to drop session-specific schema
CREATE OR REPLACE FUNCTION drop_session_schema(session_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Drop schema and all objects within it
    EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', 'session_' || session_name);
END;
$$ LANGUAGE plpgsql;

-- Create view for active sessions
CREATE OR REPLACE VIEW active_sessions AS
SELECT 
    session_id,
    user_id,
    status,
    frontend_url,
    backend_url,
    created_at,
    expires_at,
    EXTRACT(EPOCH FROM (expires_at - NOW())) AS seconds_until_expiry
FROM sessions
WHERE status IN ('active', 'creating')
AND expires_at > NOW()
ORDER BY created_at DESC;

-- Create view for session statistics
CREATE OR REPLACE VIEW session_statistics AS
SELECT 
    COUNT(*) FILTER (WHERE status = 'active') AS active_count,
    COUNT(*) FILTER (WHERE status = 'creating') AS creating_count,
    COUNT(*) FILTER (WHERE status = 'stopped') AS stopped_count,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed_count,
    COUNT(*) AS total_count,
    COUNT(DISTINCT user_id) AS unique_users,
    AVG(EXTRACT(EPOCH FROM (COALESCE(terminated_at, NOW()) - created_at))) AS avg_session_duration_seconds
FROM sessions
WHERE created_at > NOW() - INTERVAL '24 hours';

-- Grant permissions for application user (if different from postgres)
GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO postgres;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO postgres;