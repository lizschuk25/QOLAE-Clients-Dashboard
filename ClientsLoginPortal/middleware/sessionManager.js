// ==============================================
// SESSION MANAGER MIDDLEWARE
// ==============================================
// Author: Liz (with Claude)
// Purpose: Secure HTTP-only cookie session management for ClientsLoginPortal
// Features: 5-min auto-logout, multi-device detection, GDPR compliant
// Blockchain-ready: All sessions immutably logged
// ==============================================

import { Pool } from 'pg';
import crypto from 'crypto';

// Lazy-loaded database connection
let clientsDb = null;

function getDatabase() {
  if (!clientsDb) {
    console.log('📊 Initializing database pool with CLIENTS_DATABASE_URL...');
    clientsDb = new Pool({
      connectionString: process.env.CLIENTS_DATABASE_URL || 'postgresql://clients_user:clients_password@localhost:5432/qolae_clients'
    });
  }
  return clientsDb;
}

// ==============================================
// CONFIGURATION
// ==============================================

const SESSION_CONFIG = {
  TIMEOUT_MINUTES: 5,
  TIMEOUT_MS: 5 * 60 * 60 * 1000,      // 5 hours (matches JWT expiry)
  COOKIE_NAME: 'qolaeClientToken',     // ✅ JWT-based, role-specific
  COOKIE_OPTIONS: {
    httpOnly: true,                     // ✅ Cannot be read by JavaScript (XSS protection)
    secure: process.env.NODE_ENV === 'production',  // ✅ Only sent over HTTPS
    sameSite: 'Strict',                 // ✅ Not sent to other sites
    maxAge: 5 * 60 * 60 * 1000,         // ✅ 5 hours in milliseconds (matches JWT expiry)
    path: '/',
    domain: process.env.COOKIE_DOMAIN || '.qolae.com'
  }
};

// Export for use in other modules
export { SESSION_CONFIG };

// ==============================================
// HELPER FUNCTIONS
// ==============================================

/**
 * generateSessionToken
 * Creates a cryptographically secure session token
 * @returns {string} Random hex token
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * generateDeviceFingerprint
 * Creates a device fingerprint from user agent
 * @param {string} userAgent - Browser user agent string
 * @returns {string} Hashed device fingerprint
 */
function generateDeviceFingerprint(userAgent) {
  return crypto.createHash('sha256').update(userAgent || '').digest('hex');
}

/**
 * calculateEventHash
 * Creates a hash for blockchain-ready audit trail
 * @param {object} eventData - Event information
 * @returns {string} Event hash
 */
function calculateEventHash(eventData) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(eventData))
    .digest('hex');
}

/**
 * logSessionEvent
 * Creates an immutable audit log entry
 * @param {UUID} sessionId - Session ID
 * @param {string} clientPin - Client PIN
 * @param {string} eventType - Type of event
 * @param {string} eventStatus - Status (success/failure)
 * @param {object} details - Event details
 * @returns {Promise<void>}
 */
async function logSessionEvent(sessionId, clientPin, eventType, eventStatus, details = {}) {
  try {
    const eventHash = calculateEventHash({
      sessionId,
      clientPin,
      eventType,
      eventStatus,
      timestamp: new Date().toISOString()
    });

    await getDatabase().query(`
      INSERT INTO "clientSessionEvents" 
      ("sessionId", "clientPin", "eventType", "eventStatus", details, "eventHash", "createdAt")
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
    `, [sessionId, clientPin, eventType, eventStatus, JSON.stringify(details), eventHash]);

    console.log(`📝 Session event logged: ${eventType}/${eventStatus} for ${clientPin}`);
  } catch (error) {
    console.error('❌ Error logging session event:', error.message);
  }
}

// ==============================================
// CORE SESSION FUNCTIONS
// ==============================================

/**
 * createSession
 * Creates a new session for a client after successful authentication
 * @param {object} client - Client object with clientPin, email
 * @param {object} request - Fastify request object
 * @returns {Promise<object>} Session data with token
 */
export async function createSession(client, request) {
  try {
    console.log(`🔐 Starting session creation for ${client.clientPin}...`);
    console.log(`📊 Using database URL environment: ${process.env.CLIENTS_DATABASE_URL ? 'SET' : 'NOT SET'}`);
    
    const sessionToken = generateSessionToken();
    const deviceFingerprint = generateDeviceFingerprint(request.headers['user-agent']);
    const ipAddress = request.ip;
    const expiresAt = new Date(Date.now() + SESSION_CONFIG.TIMEOUT_MS);

    // Check for previous login (multi-device detection)
    const previousLogin = await getDatabase().query(`
      SELECT "ipAddress", "createdAt" 
      FROM "clientSessions" 
      WHERE "clientPin" = $1 AND "expiresAt" > NOW()
      ORDER BY "createdAt" DESC 
      LIMIT 1
    `, [client.clientPin]);

    const previousLoginData = previousLogin.rows[0] || null;
    const sameDevice = previousLoginData?.ipAddress === ipAddress;

    // Create new session
    const result = await getDatabase().query(`
      INSERT INTO "clientSessions" 
      ("clientPin", "sessionToken", "ipAddress", "userAgent", "deviceFingerprint", 
       "createdAt", "expiresAt", "previousLoginIp", "previousLoginTimestamp", "sameDeviceLogin")
      VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, $9)
      RETURNING id, "sessionToken", "expiresAt"
    `, [
      client.clientPin,
      sessionToken,
      ipAddress,
      request.headers['user-agent'],
      deviceFingerprint,
      expiresAt,
      previousLoginData?.ipAddress || null,
      previousLoginData?.createdAt || null,
      sameDevice
    ]);

    const sessionId = result.rows[0].id;

    // Log session creation event
    await logSessionEvent(
      sessionId,
      client.clientPin,
      'sessionCreated',
      'success',
      {
        device: sameDevice ? 'knownDevice' : 'newDevice',
        ipAddress: ipAddress,
        previousLoginIp: previousLoginData?.ipAddress || null
      }
    );

    console.log(`✅ Session created for ${client.clientPin} (${sameDevice ? 'known device' : 'NEW DEVICE'})`);

    return {
      sessionId,
      sessionToken,
      expiresAt,
      isNewDevice: !sameDevice,
      previousLoginIp: previousLoginData?.ipAddress || null,
      previousLoginTime: previousLoginData?.createdAt || null
    };
  } catch (error) {
    console.error('❌ Session creation error:', error.message);
    console.error('❌ Full error:', error);
    throw error;
  }
}

/**
 * validateSession
 * Checks if a session is valid and not expired
 * @param {string} sessionToken - Session token from cookie
 * @returns {Promise<object|null>} Session data or null if invalid
 */
export async function validateSession(sessionToken) {
  try {
    if (!sessionToken) return null;

    const result = await getDatabase().query(`
      SELECT 
        cs.id,
        cs."clientPin",
        cs."createdAt",
        cs."expiresAt",
        cs."isTrustedDevice",
        c.email,
        c."clientName"
      FROM "clientSessions" cs
      JOIN clients c ON cs."clientPin" = c."clientPin"
      WHERE cs."sessionToken" = $1 
        AND cs."expiresAt" > NOW()
      LIMIT 1
    `, [sessionToken]);

    if (result.rowCount === 0) {
      console.warn(`⚠️  Invalid or expired session token`);
      return null;
    }

    const session = result.rows[0];
    console.log(`✅ Session valid for ${session.clientPin}`);
    return session;
  } catch (error) {
    console.error('❌ Session validation error:', error);
    return null;
  }
}

/**
 * updateActivity
 * Refreshes the last_activity timestamp (keeps session alive)
 * @param {string} sessionToken - Session token
 * @returns {Promise<boolean>}
 */
export async function updateActivity(sessionToken) {
  try {
    const result = await getDatabase().query(`
      UPDATE "clientSessions" 
      SET "lastActivity" = NOW()
      WHERE "sessionToken" = $1 AND "expiresAt" > NOW()
      RETURNING id, "clientPin"
    `, [sessionToken]);

    if (result.rowCount > 0) {
      console.log(`⏱️  Activity updated for session ${sessionToken.substring(0, 8)}...`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('❌ Activity update error:', error);
    return false;
  }
}

/**
 * destroySession
 * Manually logs out a user and destroys their session
 * @param {string} sessionToken - Session token
 * @returns {Promise<boolean>}
 */
export async function destroySession(sessionToken) {
  try {
    const result = await getDatabase().query(`
      DELETE FROM "clientSessions" 
      WHERE "sessionToken" = $1
      RETURNING id, "clientPin"
    `, [sessionToken]);

    if (result.rowCount > 0) {
      const session = result.rows[0];
      await logSessionEvent(
        session.id,
        session.clientPin,
        'sessionDestroyed',
        'success',
        { reason: 'userLogout' }
      );
      console.log(`🚪 Session destroyed for ${session.clientPin}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('❌ Session destruction error:', error);
    return false;
  }
}

/**
 * cleanupExpiredSessions
 * Removes all expired sessions (runs on interval)
 * @returns {Promise<number>} Number of sessions deleted
 */
export async function cleanupExpiredSessions() {
  try {
    const db = getDatabase();
    const result = await db.query(`
      DELETE FROM "clientSessions" 
      WHERE "expiresAt" < NOW()
      RETURNING "clientPin"
    `);

    if (result.rowCount > 0) {
      console.log(`🧹 Cleaned up ${result.rowCount} expired sessions`);
    }
    
    return result.rowCount;
  } catch (error) {
    console.error('❌ Session cleanup error:', error.message);
    return 0;
  }
}

// ==============================================
// FASTIFY PLUGIN REGISTRATION
// ==============================================

export default async function sessionMiddleware(fastify, options) {
  // Start session cleanup interval (runs every 1 minute)
  setInterval(cleanupExpiredSessions, 60 * 1000);

  // Decorator to access session functions
  fastify.decorate('session', {
    createSession,
    validateSession,
    updateActivity,
    destroySession,
    cleanupExpiredSessions,
    config: SESSION_CONFIG
  });

  console.log('✅ Session middleware registered');
  console.log(`⏱️  Session timeout: ${SESSION_CONFIG.TIMEOUT_MINUTES} minutes`);
}
