// ==============================================
// CLIENTS DASHBOARD - AUTHENTICATION ROUTES
// ==============================================
// Purpose: 2FA authentication for clients (PIN + Email verification)
// Author: Liz 👑
// Date: 28th October 2025
// Database: qolae_lawyers (clients table)
// ==============================================

import pg from 'pg';
import crypto from 'crypto';

const { Pool } = pg;

// Database connection (Lawyers database - where clients are stored)
const lawyersDb = new Pool({
  connectionString: process.env.LAWYERS_DATABASE_URL
});

export default async function authRoutes(fastify, options) {

  // ==============================================
  // STEP 1: CLIENTS LOGIN PAGE
  // ==============================================
  fastify.get('/clients-login', async (request, reply) => {
    return reply.view('clients-login.ejs');
  });

  // ==============================================
  // STEP 2: REQUEST EMAIL VERIFICATION CODE
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

      // Check if client exists with this PIN and email in qolae_lawyers database
      const clientResult = await lawyersDb.query(
        `SELECT client_pin, name, email, status
         FROM clients
         WHERE client_pin = $1 AND email = $2`,
        [pin, email]
      );

      if (clientResult.rows.length === 0) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid Client PIN or email. Please check your invitation email.'
        });
      }

      const client = clientResult.rows[0];

      // Note: No status check - client can log in at any status to complete consent

      // Generate 6-digit verification code
      const verificationCode = crypto.randomInt(100000, 999999).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Save verification code to database
      await lawyersDb.query(
        `UPDATE clients
         SET email_verification_code = $1,
             email_verification_code_expires_at = $2,
             email_verification_code_attempts = 0,
             last_login_attempt = NOW()
         WHERE client_pin = $3`,
        [verificationCode, expiresAt, pin]
      );

      // Log activity
      await lawyersDb.query(
        `INSERT INTO client_activity_log (client_pin, activity_type, activity_description, performed_by, ip_address, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [pin, 'email_code_requested', 'Client requested email verification code', client.name, request.ip]
      );

      // TODO: Send email with verification code via NotificationService
      fastify.log.info(`Email verification code for ${email}: ${verificationCode}`);

      return reply.send({
        success: true,
        message: `Verification code sent to ${email}`,
        expiresIn: 600 // 10 minutes in seconds
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
  // STEP 3: VERIFY EMAIL CODE & LOGIN
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

      // Get client with verification code
      const clientResult = await lawyersDb.query(
        `SELECT client_pin, name, email, email_verification_code,
                email_verification_code_expires_at, email_verification_code_attempts,
                status, consent_signed_at
         FROM clients
         WHERE client_pin = $1 AND email = $2`,
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
      if (new Date() > new Date(client.email_verification_code_expires_at)) {
        return reply.code(401).send({
          success: false,
          error: 'Verification code has expired. Please request a new one.'
        });
      }

      // Check attempts (max 3)
      if (client.email_verification_code_attempts >= 3) {
        return reply.code(403).send({
          success: false,
          error: 'Too many failed attempts. Please request a new verification code.'
        });
      }

      // Verify code
      if (client.email_verification_code !== code) {
        // Increment failed attempts
        await lawyersDb.query(
          `UPDATE clients
           SET email_verification_code_attempts = email_verification_code_attempts + 1
           WHERE client_pin = $1`,
          [pin]
        );

        return reply.code(401).send({
          success: false,
          error: 'Invalid verification code',
          attemptsRemaining: 2 - client.email_verification_code_attempts
        });
      }

      // Code is valid - clear verification code and generate JWT
      await lawyersDb.query(
        `UPDATE clients
         SET email_verification_code = NULL,
             email_verification_code_expires_at = NULL,
             email_verification_code_attempts = 0,
             last_login = NOW(),
             total_logins = COALESCE(total_logins, 0) + 1
         WHERE client_pin = $1`,
        [pin]
      );

      // Log successful login
      await lawyersDb.query(
        `INSERT INTO client_activity_log (client_pin, activity_type, activity_description, performed_by, ip_address, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [pin, 'successful_login', `Client logged in successfully`, client.name, request.ip]
      );

      // Generate JWT token
      const token = fastify.jwt.sign({
        pin: client.client_pin,
        name: client.name,
        email: client.email,
        role: 'client'
      });

      // Set secure cookie
      reply.setCookie('qolae_client_token', token, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 5 * 60 * 60 // 5 hours
      });

      return reply.send({
        success: true,
        message: 'Login successful',
        redirectTo: '/clients-dashboard',
        client: {
          pin: client.client_pin,
          name: client.name,
          email: client.email,
          status: client.status,
          consentSignedAt: client.consent_signed_at
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
  // LOGOUT
  // ==============================================
  fastify.post('/api/clients/logout', async (request, reply) => {
    try {
      // Clear cookie
      reply.clearCookie('qolae_client_token', {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });

      return reply.send({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      fastify.log.error('Error logging out:', error);
      return reply.code(500).send({
        success: false,
        error: 'Failed to logout'
      });
    }
  });
}

