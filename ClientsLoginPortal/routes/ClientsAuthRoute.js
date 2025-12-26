// ==============================================
// CLIENTS LOGIN PORTAL - AUTHENTICATION ROUTES
// ==============================================
// Purpose: 2FA authentication for clients (PIN + Email verification)
// Author: Liz
// Date: 26th December 2025
// Database: qolae_lawyers (consentForms table)
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import pg from 'pg';
import crypto from 'crypto';

const { Pool } = pg;

// ==============================================
// LOCATION BLOCK B: DATABASE CONNECTION
// ==============================================
const lawyersDb = new Pool({
    connectionString: process.env.LAWYERS_DATABASE_URL
});

// ==============================================
// LOCATION BLOCK C: ROUTES EXPORT
// ==============================================
export default async function clientsAuthRoute(fastify, options) {

    // ==============================================
    // LOCATION BLOCK 1: LOGIN PAGE (STEP 1 - PIN & EMAIL)
    // ==============================================
    fastify.get('/clients-login', async (request, reply) => {
        // Check if already authenticated
        try {
            await request.jwtVerify();
            // Already logged in, redirect to dashboard
            return reply.redirect(process.env.DASHBOARD_URL || 'https://clients.qolae.com/clients-dashboard');
        } catch (err) {
            // Not logged in, show login page
        }

        return reply.view('clients-login.ejs', {
            error: request.query.error || null,
            message: request.query.message || null
        });
    });

    // ==============================================
    // LOCATION BLOCK 2: REQUEST EMAIL VERIFICATION CODE
    // ==============================================
    fastify.post('/api/clients/request-email-code', async (request, reply) => {
        const { pin, email } = request.body;

        try {
            // Validate input
            if (!pin || !email) {
                return reply.code(400).send({
                    success: false,
                    error: 'Client PIN and email are required'
                });
            }

            // Check if client exists with this PIN and email in consentForms table
            const clientResult = await lawyersDb.query(
                `SELECT "clientPin", "clientName", "clientEmail", "status"
                 FROM "consentForms"
                 WHERE "clientPin" = $1 AND "clientEmail" = $2`,
                [pin, email]
            );

            if (clientResult.rows.length === 0) {
                return reply.code(401).send({
                    success: false,
                    error: 'Invalid Client PIN or email. Please check your invitation email.'
                });
            }

            const client = clientResult.rows[0];

            // Generate 6-digit verification code
            const verificationCode = crypto.randomInt(100000, 999999).toString();
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

            // Save verification code to database
            await lawyersDb.query(
                `UPDATE "consentForms"
                 SET "emailVerificationCode" = $1,
                     "emailVerificationCodeExpiresAt" = $2,
                     "emailVerificationCodeAttempts" = 0,
                     "lastLoginAttempt" = NOW()
                 WHERE "clientPin" = $3`,
                [verificationCode, expiresAt, pin]
            );

            // Log activity
            await lawyersDb.query(
                `INSERT INTO "clientActivityLog" ("clientPin", "activityType", "activityDescription", "performedBy", "ipAddress", "createdAt")
                 VALUES ($1, $2, $3, $4, $5, NOW())`,
                [pin, 'emailCodeRequested', 'Client requested email verification code', client.clientName, request.ip]
            );

            // TODO: Send email with verification code via API-Dashboard NotificationService
            // For now, log it (remove in production)
            fastify.log.info(`[DEV] Email verification code for ${email}: ${verificationCode}`);

            return reply.send({
                success: true,
                message: `Verification code sent to ${email}`,
                expiresIn: 600,
                redirectTo: '/clients-2fa',
                clientName: client.clientName.split(' ')[0] // First name only
            });

        } catch (error) {
            fastify.log.error('Error requesting email code:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to send verification code'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 3: 2FA PAGE (STEP 2 - VERIFICATION CODE)
    // ==============================================
    fastify.get('/clients-2fa', async (request, reply) => {
        const { pin, email, name } = request.query;

        if (!pin || !email) {
            return reply.redirect('/clients-login?error=Please start from the login page');
        }

        return reply.view('clients-2fa.ejs', {
            pin: pin,
            email: email,
            clientName: name || 'Client',
            error: request.query.error || null
        });
    });

    // ==============================================
    // LOCATION BLOCK 4: VERIFY EMAIL CODE & CREATE SESSION
    // ==============================================
    fastify.post('/api/clients/verify-email-code', async (request, reply) => {
        const { pin, email, code } = request.body;

        try {
            // Validate input
            if (!pin || !email || !code) {
                return reply.code(400).send({
                    success: false,
                    error: 'Client PIN, email, and verification code are required'
                });
            }

            // Get client with verification code from consentForms
            const clientResult = await lawyersDb.query(
                `SELECT "clientPin", "clientName", "clientEmail", "emailVerificationCode",
                        "emailVerificationCodeExpiresAt", "emailVerificationCodeAttempts",
                        "status", "consentSignedAt"
                 FROM "consentForms"
                 WHERE "clientPin" = $1 AND "clientEmail" = $2`,
                [pin, email]
            );

            if (clientResult.rows.length === 0) {
                return reply.code(401).send({
                    success: false,
                    error: 'Invalid Client PIN or email'
                });
            }

            const client = clientResult.rows[0];

            // Check if code has expired
            if (new Date() > new Date(client.emailVerificationCodeExpiresAt)) {
                return reply.code(401).send({
                    success: false,
                    error: 'Verification code has expired. Please request a new one.'
                });
            }

            // Check attempts (max 3)
            if (client.emailVerificationCodeAttempts >= 3) {
                return reply.code(403).send({
                    success: false,
                    error: 'Too many failed attempts. Please request a new verification code.'
                });
            }

            // Verify code
            if (client.emailVerificationCode !== code) {
                // Increment failed attempts
                await lawyersDb.query(
                    `UPDATE "consentForms"
                     SET "emailVerificationCodeAttempts" = "emailVerificationCodeAttempts" + 1
                     WHERE "clientPin" = $1`,
                    [pin]
                );

                return reply.code(401).send({
                    success: false,
                    error: 'Invalid verification code',
                    attemptsRemaining: 2 - client.emailVerificationCodeAttempts
                });
            }

            // Code is valid - clear verification code and update login stats
            await lawyersDb.query(
                `UPDATE "consentForms"
                 SET "emailVerificationCode" = NULL,
                     "emailVerificationCodeExpiresAt" = NULL,
                     "emailVerificationCodeAttempts" = 0,
                     "lastLogin" = NOW(),
                     "totalLogins" = COALESCE("totalLogins", 0) + 1
                 WHERE "clientPin" = $1`,
                [pin]
            );

            // Log successful login
            await lawyersDb.query(
                `INSERT INTO "clientActivityLog" ("clientPin", "activityType", "activityDescription", "performedBy", "ipAddress", "createdAt")
                 VALUES ($1, $2, $3, $4, $5, NOW())`,
                [pin, 'successfulLogin', 'Client logged in successfully via 2FA', client.clientName, request.ip]
            );

            // Generate JWT token
            const token = fastify.jwt.sign({
                pin: client.clientPin,
                name: client.clientName,
                email: client.clientEmail,
                role: 'client'
            });

            // Set secure cookie (production - HTTPS)
            reply.setCookie('qolaeClientToken', token, {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 5 * 60 * 60, // 5 hours
                domain: process.env.COOKIE_DOMAIN || '.qolae.com'
            });

            // Redirect to dashboard
            const dashboardUrl = process.env.DASHBOARD_URL || 'https://clients.qolae.com/clients-dashboard';

            return reply.send({
                success: true,
                message: 'Login successful',
                redirectTo: dashboardUrl,
                client: {
                    pin: client.clientPin,
                    name: client.clientName,
                    email: client.clientEmail,
                    status: client.status,
                    consentSignedAt: client.consentSignedAt
                }
            });

        } catch (error) {
            fastify.log.error('Error verifying email code:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to verify code'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 5: RESEND VERIFICATION CODE
    // ==============================================
    fastify.post('/api/clients/resend-code', async (request, reply) => {
        const { pin, email } = request.body;

        // Reuse the request-email-code logic
        return fastify.inject({
            method: 'POST',
            url: '/api/clients/request-email-code',
            payload: { pin, email }
        }).then(response => {
            reply.code(response.statusCode).send(JSON.parse(response.payload));
        });
    });

    // ==============================================
    // LOCATION BLOCK 6: LOGOUT
    // ==============================================
    fastify.post('/api/clients/logout', async (request, reply) => {
        try {
            // Clear cookie (production - HTTPS)
            reply.clearCookie('qolaeClientToken', {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                domain: process.env.COOKIE_DOMAIN || '.qolae.com'
            });

            return reply.send({
                success: true,
                message: 'Logged out successfully',
                redirectTo: '/clients-login'
            });
        } catch (error) {
            fastify.log.error('Error logging out:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to logout'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 7: CHECK AUTH STATUS
    // ==============================================
    fastify.get('/api/clients/auth-status', async (request, reply) => {
        try {
            await request.jwtVerify();
            return reply.send({
                authenticated: true,
                client: {
                    pin: request.user.pin,
                    name: request.user.name,
                    email: request.user.email
                }
            });
        } catch (error) {
            return reply.send({
                authenticated: false
            });
        }
    });
}