-- ==============================================
-- QOLAE CLIENTS LOGIN PORTAL - SESSION INFRASTRUCTURE
-- ==============================================
-- Purpose: Database tables for client authentication and session management
-- Author: Liz
-- Date: 26th December 2025
-- Database: qolae_lawyers
-- ==============================================

-- ==============================================
-- LOCATION BLOCK 1: ADD 2FA COLUMNS TO consentForms TABLE
-- ==============================================
-- These columns support PIN + Email verification flow

ALTER TABLE "consentForms"
ADD COLUMN IF NOT EXISTS "emailVerificationCode" VARCHAR(6),
ADD COLUMN IF NOT EXISTS "emailVerificationCodeExpiresAt" TIMESTAMP,
ADD COLUMN IF NOT EXISTS "emailVerificationCodeAttempts" INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS "lastLoginAttempt" TIMESTAMP,
ADD COLUMN IF NOT EXISTS "lastLogin" TIMESTAMP,
ADD COLUMN IF NOT EXISTS "totalLogins" INTEGER DEFAULT 0;

-- ==============================================
-- LOCATION BLOCK 2: CLIENT ACTIVITY LOG TABLE
-- ==============================================
-- GDPR-compliant audit trail for all client actions

CREATE TABLE IF NOT EXISTS "clientActivityLog" (
    "id" SERIAL PRIMARY KEY,
    "clientPin" VARCHAR(50) NOT NULL,
    "activityType" VARCHAR(100) NOT NULL,
    "activityDescription" TEXT,
    "performedBy" VARCHAR(255),
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT "fk_clientActivityLog_consentForms"
        FOREIGN KEY ("clientPin")
        REFERENCES "consentForms"("clientPin")
        ON DELETE CASCADE
);

-- Index for fast lookups by client
CREATE INDEX IF NOT EXISTS "idx_clientActivityLog_clientPin" 
ON "clientActivityLog"("clientPin");

-- Index for activity type queries
CREATE INDEX IF NOT EXISTS "idx_clientActivityLog_activityType" 
ON "clientActivityLog"("activityType");

-- Index for date range queries
CREATE INDEX IF NOT EXISTS "idx_clientActivityLog_createdAt" 
ON "clientActivityLog"("createdAt" DESC);

-- ==============================================
-- LOCATION BLOCK 3: CLIENT NOTIFICATIONS TABLE
-- ==============================================
-- Notifications displayed in client dashboard

CREATE TABLE IF NOT EXISTS "clientNotifications" (
    "id" SERIAL PRIMARY KEY,
    "clientPin" VARCHAR(50) NOT NULL,
    "title" VARCHAR(255) NOT NULL,
    "message" TEXT NOT NULL,
    "type" VARCHAR(50) DEFAULT 'info',
    "read" BOOLEAN DEFAULT FALSE,
    "readAt" TIMESTAMP,
    "actionUrl" VARCHAR(500),
    "metadata" JSONB,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "expiresAt" TIMESTAMP,
    
    CONSTRAINT "fk_clientNotifications_consentForms"
        FOREIGN KEY ("clientPin")
        REFERENCES "consentForms"("clientPin")
        ON DELETE CASCADE
);

-- Index for fast lookups by client
CREATE INDEX IF NOT EXISTS "idx_clientNotifications_clientPin" 
ON "clientNotifications"("clientPin");

-- Index for unread notifications
CREATE INDEX IF NOT EXISTS "idx_clientNotifications_unread" 
ON "clientNotifications"("clientPin", "read") 
WHERE "read" = FALSE;

-- ==============================================
-- LOCATION BLOCK 4: CLIENT SESSIONS TABLE (OPTIONAL)
-- ==============================================
-- For tracking active sessions (if needed beyond JWT)

CREATE TABLE IF NOT EXISTS "clientSessions" (
    "id" SERIAL PRIMARY KEY,
    "clientPin" VARCHAR(50) NOT NULL,
    "sessionToken" VARCHAR(500) UNIQUE NOT NULL,
    "ipAddress" VARCHAR(45),
    "userAgent" TEXT,
    "isActive" BOOLEAN DEFAULT TRUE,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "expiresAt" TIMESTAMP NOT NULL,
    "lastActivityAt" TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT "fk_clientSessions_consentForms"
        FOREIGN KEY ("clientPin")
        REFERENCES "consentForms"("clientPin")
        ON DELETE CASCADE
);

-- Index for session lookups
CREATE INDEX IF NOT EXISTS "idx_clientSessions_token" 
ON "clientSessions"("sessionToken");

-- Index for active sessions by client
CREATE INDEX IF NOT EXISTS "idx_clientSessions_active" 
ON "clientSessions"("clientPin", "isActive") 
WHERE "isActive" = TRUE;

-- ==============================================
-- LOCATION BLOCK 5: COMMON ACTIVITY TYPES REFERENCE
-- ==============================================
-- Reference for activityType values used in clientActivityLog:
--
-- Authentication:
--   'emailCodeRequested'  - Client requested email verification code
--   'emailCodeVerified'   - Client successfully verified email code
--   'emailCodeFailed'     - Client failed to verify email code
--   'successfulLogin'     - Client logged in successfully via 2FA
--   'failedLogin'         - Client login attempt failed
--   'logout'              - Client logged out
--
-- Consent:
--   'consentViewed'       - Client viewed consent form
--   'consentDownloaded'   - Client downloaded consent form
--   'consentSigned'       - Client signed consent form digitally
--   'consentUploaded'     - Client uploaded signed consent form
--
-- Documents:
--   'documentViewed'      - Client viewed a document
--   'documentDownloaded'  - Client downloaded a document
--
-- Appointments:
--   'appointmentViewed'   - Client viewed appointment details
--   'appointmentScheduled'- Client scheduled an appointment
--
-- Reports:
--   'reportViewed'        - Client viewed final report

-- ==============================================
-- LOCATION BLOCK 6: CLEANUP FUNCTION FOR EXPIRED CODES
-- ==============================================
-- Run periodically to clear expired verification codes

CREATE OR REPLACE FUNCTION cleanup_expired_verification_codes()
RETURNS INTEGER AS $$
DECLARE
    rows_updated INTEGER;
BEGIN
    UPDATE "consentForms"
    SET "emailVerificationCode" = NULL,
        "emailVerificationCodeExpiresAt" = NULL,
        "emailVerificationCodeAttempts" = 0
    WHERE "emailVerificationCodeExpiresAt" < NOW()
      AND "emailVerificationCode" IS NOT NULL;
    
    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    RETURN rows_updated;
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- LOCATION BLOCK 7: CLEANUP FUNCTION FOR OLD SESSIONS
-- ==============================================
-- Run periodically to clear expired sessions

CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    DELETE FROM "clientSessions"
    WHERE "expiresAt" < NOW();
    
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- LOCATION BLOCK 8: GRANT PERMISSIONS (ADJUST AS NEEDED)
-- ==============================================
-- GRANT SELECT, INSERT, UPDATE ON "clientActivityLog" TO qolae_app_user;
-- GRANT SELECT, INSERT, UPDATE ON "clientNotifications" TO qolae_app_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON "clientSessions" TO qolae_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO qolae_app_user;
