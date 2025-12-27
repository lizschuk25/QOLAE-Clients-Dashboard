// ==============================================
// CLIENTS LOGIN PORTAL - SESSION MANAGER MIDDLEWARE
// ==============================================
// Purpose: JWT verification and session management for clients
// Author: Liz
// Date: 26th December 2025
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import pg from 'pg';

const { Pool } = pg;

// Database connection
const clientsDb = new Pool({
    connectionString: process.env.CLIENTS_DATABASE_URL
});

// ==============================================
// LOCATION BLOCK 1: VERIFY CLIENT SESSION
// ==============================================
/**
 * Middleware to verify client JWT token
 * Attaches client data to request.user if valid
 * Redirects to login if invalid/expired
 */
export async function verifyClientSession(request, reply) {
    try {
        // Verify JWT from cookie
        await request.jwtVerify();

        // Check role
        if (request.user.role !== 'client') {
            throw new Error('Invalid role');
        }

        // Optionally verify client still exists in database
        const clientResult = await clientsDb.query(
            `SELECT "clientPin", "clientName", "clientEmail", "workflowStatus"
             FROM "clients"
             WHERE "clientPin" = $1`,
            [request.user.pin]
        );

        if (clientResult.rows.length === 0) {
            throw new Error('Client not found');
        }

        // Attach fresh client data to request
        request.clientData = clientResult.rows[0];

    } catch (error) {
        // Clear invalid cookie
        reply.clearCookie('qolaeClientToken', {
            path: '/',
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: process.env.COOKIE_DOMAIN || '.qolae.com'
        });

        // Redirect to login
        return reply.redirect('/clients-login?error=Session expired. Please login again.');
    }
}

// ==============================================
// LOCATION BLOCK 2: VERIFY CLIENT API (NO REDIRECT)
// ==============================================
/**
 * Middleware for API routes - returns 401 instead of redirect
 * Use for AJAX/fetch requests
 */
export async function verifyClientAPI(request, reply) {
    try {
        await request.jwtVerify();

        if (request.user.role !== 'client') {
            throw new Error('Invalid role');
        }

    } catch (error) {
        return reply.code(401).send({
            success: false,
            error: 'Authentication required',
            redirectTo: '/clients-login'
        });
    }
}

// ==============================================
// LOCATION BLOCK 3: CHECK IF AUTHENTICATED (NO BLOCK)
// ==============================================
/**
 * Soft check - doesn't block if not authenticated
 * Just attaches user data if token is valid
 */
export async function checkClientAuth(request, reply) {
    try {
        await request.jwtVerify();
        request.isAuthenticated = true;
    } catch (error) {
        request.isAuthenticated = false;
    }
}

// ==============================================
// LOCATION BLOCK 4: REFRESH SESSION
// ==============================================
/**
 * Extends session expiry if valid
 * Call on active user interactions
 */
export async function refreshClientSession(request, reply) {
    try {
        await request.jwtVerify();

        // Generate new token with extended expiry
        const token = reply.jwtSign({
            pin: request.user.pin,
            name: request.user.name,
            email: request.user.email,
            role: 'client'
        });

        // Set refreshed cookie
        reply.setCookie('qolaeClientToken', token, {
            path: '/',
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 5 * 60 * 60, // 5 hours
            domain: process.env.COOKIE_DOMAIN || '.qolae.com'
        });

    } catch (error) {
        // Silently fail - don't block the request
    }
}

// ==============================================
// LOCATION BLOCK 5: LOG CLIENT ACTIVITY
// ==============================================
/**
 * Logs client activity to audit trail
 */
export async function logClientActivity(clientPin, activityType, description, performedBy, ipAddress) {
    try {
        await clientsDb.query(
            `INSERT INTO "clientActivityLog" ("clientPin", "activityType", "activityDescription", "performedBy", "ipAddress", "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [clientPin, activityType, description, performedBy, ipAddress]
        );
    } catch (error) {
        console.error('Failed to log client activity:', error);
    }
}

// ==============================================
// LOCATION BLOCK 6: EXPORT DEFAULT
// ==============================================
export default {
    verifyClientSession,
    verifyClientAPI,
    checkClientAuth,
    refreshClientSession,
    logClientActivity
};