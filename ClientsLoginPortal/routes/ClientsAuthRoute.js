// ==============================================
// clientsAuthRoute.js - Clients Authentication Routes
// THE BRIDGE: Clients-specific authentication routes
// Author: Liz 👑
// GDPR CRITICAL: All auth attempts must be logged
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// A.1: Core Dependencies
// A.2: API Configuration
// A.3: Environment Variables & Secrets
// ==============================================

// A.1: Core Dependencies
import ssotFetch from '../utils/ssotFetch.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// A.2: API Configuration
// ssotFetch handles SSOT base URL and x-internal-secret automatically

// ClientsDashboard baseURL for redirects
const CLIENTS_DASHBOARD_BASE_URL = 'https://clients.qolae.com';

// A.3: JWT Secret - fail fast if not configured
const JWT_SECRET = process.env.CLIENTS_LOGIN_JWT_SECRET || (() => {
  console.error('CLIENTS_LOGIN_JWT_SECRET not found in environment variables!');
  throw new Error('CLIENTS_LOGIN_JWT_SECRET environment variable is required');
})();

// ==============================================
// LOCATION BLOCK B: ROUTE DEFINITIONS
// B.1: Login Route
// B.2: Email Verification Code Request
// B.3: 2FA Verification Route
// B.4: Logout Route
// B.5: Session Check Route
// ==============================================

export default async function clientsAuthRoutes(fastify, opts) {
  
  // ==============================================
  // B.1: CLIENTS LOGIN WITH PIN (FROM EMAIL CLICK)
  // ==============================================
  
  fastify.post('/clientsAuth/login', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '15 minutes',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    const { email, clientPin } = request.body;
    const clientIP = request.ip;
    
    // 📝 GDPR Audit Log
    fastify.log.info({
      event: 'clientLoginAttempt',
      clientPin: clientPin,
      email: email,
      ip: clientIP,
      timestamp: new Date().toISOString(),
      gdprCategory: 'authentication'
    });
    
    if (!email || !clientPin) {
      return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin || ''}&error=${encodeURIComponent('Email and Client PIN are required')}`);
    }
    
    try {
      // Validate Client PIN format first (using SSOT with userType)
      const pinValidationRes = await ssotFetch('/api/pin/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: clientPin, userType: 'client' })
      });
      const pinValidation = await pinValidationRes.json();

      if (!pinValidationRes.ok || !pinValidation.validation?.isValid) {
        fastify.log.warn({
          event: 'invalidPinFormat',
          clientPin: clientPin,
          errors: pinValidation.validation?.errors
        });

        return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Invalid Client PIN format')}`);
      }
      
      // Call SSOT API for authentication
      const apiRes = await ssotFetch('/auth/clients/requestToken', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientEmail: email, clientPin, source: 'clients-portal', ip: clientIP })
      });
      const apiResponse = await apiRes.json();

      if (!apiRes.ok || !apiResponse.success) {
        fastify.log.warn({
          event: 'clientLoginFailed',
          clientPin: clientPin,
          error: apiResponse.error
        });
        return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent(apiResponse.error || 'Authentication failed')}`);
      }

      // GDPR Audit: Successful login
      fastify.log.info({
        event: 'clientLoginSuccess',
        clientPin: clientPin,
        consentSigned: apiResponse.client.consentSigned,
        assignedLawyerPin: apiResponse.client.assignedLawyerPin
      });

        // ============================================
        // REUSE SESSION FROM PIN-ACCESS (NO NEW SESSION)
        // ============================================

        try {
          // Read existing JWT token from cookie (set by pin-access)
          const jwtToken = request.cookies?.qolaeClientToken;

          if (!jwtToken) {
            fastify.log.warn({
              event: 'loginNoJWT',
              clientPin: clientPin,
              gdprCategory: 'authentication'
            });
            return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Session expired. Please click your PIN link again.')}`);
          }

          // SSOT: Validate JWT token (replaces 3 direct DB queries)
          const valRes = await ssotFetch('/auth/clients/session/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: jwtToken })
          });
          const validationResponse = await valRes.json();

          if (!valRes.ok || !validationResponse.success || !validationResponse.valid) {
            fastify.log.warn({
              event: 'loginInvalidJWT',
              clientPin: clientPin,
              error: validationResponse.error || 'Invalid token',
              gdprCategory: 'authentication'
            });
            return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Session expired. Please click your PIN link again.')}`);
          }

          // Verify PIN matches JWT payload
          const clientData = validationResponse.client;
          if (clientData.clientPin !== clientPin) {
            fastify.log.info({
              event: 'loginPinMismatch',
              expectedPin: clientData.clientPin,
              providedPin: clientPin,
              action: 'clearingOldCookie',
              gdprCategory: 'authentication'
            });
            // Clear old cookie and redirect to get fresh JWT for new PIN
            reply.clearCookie('qolaeClientToken', {
              path: '/',
              domain: process.env.COOKIE_DOMAIN || '.qolae.com'
            });
            // Redirect to GET /clientsLogin which will create fresh JWT via SSOT
            return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}`);
          }

          // Log JWT validation success
          fastify.log.info({
            event: 'jwtValidated',
            clientPin: clientPin,
            expiresAt: validationResponse.expiresAt,
            gdprCategory: 'authentication'
          });

          // ✅ NO NEW COOKIE NEEDED - JWT already set by pin-access
          // ✅ NO SESSION UPDATE NEEDED - JWT is stateless
          // Redirect to 2FA page
          return reply.code(302).redirect('/clients2fa');

        } catch (sessionError) {
          fastify.log.error({
            event: 'sessionCreationError',
            clientPin: clientPin,
            error: sessionError.message,
            stack: sessionError.stack
          });

          return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Failed to create session. Please try again.')}`);
        }
    } catch (err) {
      // GDPR Audit: System error
      fastify.log.error({
        event: 'clientLoginError',
        clientPin: clientPin,
        error: err.message,
        stack: err.stack
      });

      // SERVER-SIDE: Redirect with system error
      return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin || ''}&error=${encodeURIComponent('Authentication service unavailable. Please try again.')}`);
    }
  });
  
  // ==============================================
  // B.2: REQUEST EMAIL VERIFICATION CODE (SESSION-BASED)
  // ==============================================
  // ⚠️ REFACTORED: Now uses SSOT endpoint /auth/clients/2fa/request-code

  fastify.post('/clientsAuth/requestEmailCode', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '10 minutes',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    const clientIP = request.ip;

    // ✅ STEP 1: Read JWT token from HTTP-only cookie
    const sessionId = request.cookies?.qolaeClientToken;

    if (!sessionId) {
      fastify.log.warn({
        event: 'verificationCodeRequestNoSession',
        ip: clientIP,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent('No active session. Please log in again.'));
    }

    try {
      // STEP 2: Call SSOT endpoint with JWT in Authorization header
      const ssotRes = await ssotFetch('/auth/clients/2fa/requestCode', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionId}`
        },
        body: JSON.stringify({
          ipAddress: clientIP,
          userAgent: request.headers['user-agent']
        })
      });

      const ssotData = await ssotRes.json();

      if (!ssotRes.ok) {
        if (ssotRes.status === 401) {
          fastify.log.warn({
            event: 'verificationCodeRequestInvalidSession',
            error: ssotData.error,
            ip: clientIP,
            gdprCategory: 'authentication'
          });
          return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent(ssotData.error || 'Session invalid. Please log in again.'));
        }
        return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(ssotData.error || 'Failed to send verification code'));
      }

      if (ssotData.success) {
        // 📝 GDPR Audit: Verification code requested
        fastify.log.info({
          event: 'verificationCodeRequested',
          clientPin: ssotData.client?.clientPin,
          email: ssotData.client?.email,
          sessionId: sessionId.substring(0, 10) + '...',
          gdprCategory: 'authentication'
        });

        // ✅ SERVER-SIDE: Redirect back to 2FA page with success message
        return reply.code(302).redirect('/clients2fa?codeSent=true');
      } else {
        fastify.log.warn({
          event: 'verificationCodeRequestApiFailed',
          error: ssotData.error,
          gdprCategory: 'authentication'
        });

        return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(ssotData.error || 'Failed to send verification code'));
      }
    } catch (err) {
      // GDPR Audit: System error (network/parse failures only)
      fastify.log.error({
        event: 'verificationCodeRequestError',
        error: err.message,
        stack: err.stack,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent('Verification code service unavailable'));
    }
  });
  
  // ==============================================
  // B.3: 2FA VERIFICATION (SESSION-BASED)
  // ==============================================
  // ⚠️ REFACTORED: Now uses SSOT endpoint /auth/clients/2fa/verify-code

  fastify.post('/clientsAuth/verify2fa', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '10 minutes',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    const { verificationCode } = request.body;
    const clientIP = request.ip;

    // 📝 GDPR Audit Log
    fastify.log.info({
      event: '2faVerificationAttempt',
      ip: clientIP,
      timestamp: new Date().toISOString(),
      gdprCategory: 'authentication'
    });

    // ✅ STEP 1: Read JWT token from HTTP-only cookie
    const sessionId = request.cookies?.qolaeClientToken;

    if (!sessionId) {
      fastify.log.warn({
        event: '2faVerificationNoSession',
        ip: clientIP,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent('No active session. Please log in again.'));
    }

    if (!verificationCode) {
      return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent('Verification code required'));
    }

    try {
      // STEP 2: Call SSOT endpoint with JWT in Authorization header
      const ssotRes = await ssotFetch('/auth/clients/2fa/verifyCode', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionId}`
        },
        body: JSON.stringify({
          verificationCode: verificationCode,
          ipAddress: clientIP,
          userAgent: request.headers['user-agent']
        })
      });

      const ssotData = await ssotRes.json();

      if (!ssotRes.ok) {
        if (ssotRes.status === 401) {
          fastify.log.warn({
            event: '2faVerificationInvalidSession',
            error: ssotData.error,
            ip: clientIP,
            gdprCategory: 'authentication'
          });
          if (ssotData.redirect) {
            return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent(ssotData.error || 'Session invalid. Please log in again.'));
          }
          return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(ssotData.error || 'Invalid verification code'));
        }
        return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(ssotData.error || '2FA verification failed'));
      }

      if (ssotData.success) {
        const clientPin = ssotData.client.clientPin;
        const clientData = ssotData.client;

        // ============================================
        // STEP 3: USE JWT FROM SSOT RESPONSE
        // ============================================
        // ✅ SSOT COMPLIANT: JWT generated & stored by SSOT endpoint
        // No local generation, no direct database access

        const jwtToken = ssotData.accessToken;

        fastify.log.info({ event: 'jwtReceived', clientPin });

        // 📝 GDPR Audit: Successful 2FA
        fastify.log.info({
          event: '2faVerificationSuccess',
          clientPin: clientPin,
          assignedLawyerPin: clientData.assignedLawyerPin,
          sessionId: sessionId.substring(0, 10) + '...',
          jwtReceived: !!jwtToken,
          gdprCategory: 'authentication'
        });

        // ============================================
        // STEP 4: REDIRECT BASED ON PASSWORD SETUP STATUS
        // ============================================
        // (passwordSetupCompleted is returned from SSOT)

        if (ssotData.passwordSetupCompleted) {
          // Returning client - redirect to secure login with password entry
          return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin}&setupCompleted=true`);
        } else {
          // New client - redirect to secure login for password setup
          return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin}&verified=true`);
        }
      }
    } catch (err) {
      // GDPR Audit: System error (network/parse failures only)
      fastify.log.error({
        event: '2faVerificationError',
        error: err.message,
        stack: err.stack,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent('2FA verification service unavailable'));
    }
  });

  // ==============================================
  // B.3.5: SECURE LOGIN - PASSWORD SETUP/VERIFY
  // ==============================================
  // Handles password form submission after 2FA verification
  // Routes to either passwordSetup (new) or passwordVerify (returning)

  fastify.post('/clientsAuth/secureLogin', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '15 minutes',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    const { password, passwordConfirm, isNewUser, reset, clientPin } = request.body;
    const clientIP = request.ip;

    // 📝 GDPR Audit Log
    fastify.log.info({
      event: 'secureLoginAttempt',
      isNewUser: isNewUser,
      reset: reset,
      ip: clientIP,
      timestamp: new Date().toISOString(),
      gdprCategory: 'authentication'
    });

    // ✅ STEP 1: Read JWT token from HTTP-only cookie
    const jwtToken = request.cookies?.qolaeClientToken;

    if (!jwtToken) {
      fastify.log.warn({
        event: 'secureLoginNoSession',
        ip: clientIP,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent('Session expired. Please click your PIN link again.'));
    }

    if (!password) {
      return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=` + encodeURIComponent('Password is required'));
    }

    // Server-side password match validation (for new users and password reset)
    if (passwordConfirm && password !== passwordConfirm) {
      fastify.log.warn({
        event: 'passwordMismatch',
        clientPin: clientPin,
        ip: clientIP,
        gdprCategory: 'authentication'
      });
      return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=${encodeURIComponent('Passwords do not match. Please try again.')}`);
    }

    const isReset = reset === 'true' || reset === true;

    try {
      // ✅ STEP 2: Determine which SSOT endpoint to call (3-way: reset / setup / verify)
      const endpoint = isReset
        ? '/auth/clients/passwordReset'
        : (isNewUser === 'true' || isNewUser === true)
          ? '/auth/clients/passwordSetup'
          : '/auth/clients/passwordVerify';

      fastify.log.info({ event: 'ssotCall', endpoint });

      // passwordReset takes PIN in body (no JWT auth header needed)
      // passwordSetup and passwordVerify use JWT auth header
      const requestBody = isReset
        ? { clientPin: clientPin, password: password, ipAddress: clientIP, userAgent: request.headers['user-agent'] }
        : { password: password, ipAddress: clientIP, userAgent: request.headers['user-agent'] };

      const requestConfig = isReset
        ? {}
        : { headers: { 'Authorization': `Bearer ${jwtToken}` } };

      const ssotRes = await ssotFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(requestConfig.headers || {})
        },
        body: JSON.stringify(requestBody)
      });

      const ssotData = await ssotRes.json();

      if (!ssotRes.ok) {
        if (ssotRes.status === 401) {
          const apiError = ssotData.error || '';
          const isInvalidPassword = apiError.toLowerCase().includes('invalid password');

          fastify.log.warn({
            event: isInvalidPassword ? 'secureLoginInvalidPassword' : 'secureLoginInvalidSession',
            error: apiError,
            ip: clientIP,
            gdprCategory: 'authentication'
          });

          if (isInvalidPassword) {
            const resetParam = isReset ? '&reset=true' : '';
            return reply.code(302).redirect('/secureLogin?clientPin=' + encodeURIComponent(clientPin || '') + resetParam + '&error=' + encodeURIComponent('Invalid password. Please try again.'));
          }
          return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent('Session expired. Please click your PIN link again.'));
        }

        if (ssotRes.status === 409) {
          return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&setupCompleted=true&error=` + encodeURIComponent('Password already set up. Please enter your password.'));
        }

        return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=` + encodeURIComponent(ssotData.error || 'Password operation failed'));
      }

      if (ssotData.success) {
        if (ssotData.accessToken) {
          reply.setCookie('qolaeClientToken', ssotData.accessToken, {
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 24
          });

          const opType = isReset ? 'reset' : (isNewUser ? 'setup' : 'verify');
          fastify.log.info({ event: 'jwtCookieUpdated', operation: opType });
        }

        const eventName = isReset ? 'passwordResetSuccess' : (isNewUser ? 'passwordSetupSuccess' : 'passwordVerifySuccess');
        fastify.log.info({
          event: eventName,
          clientPin: ssotData.client?.clientPin,
          gdprCategory: 'authentication'
        });

        // ✅ STEP 5: Redirect to Dashboard with Client PIN parameter
        const ssotClientPin = ssotData.client?.clientPin;
        if (!ssotClientPin) {
          return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=` + encodeURIComponent('Session data incomplete'));
        }
        return reply.code(302).redirect(`/clientsDashboard?clientPin=${encodeURIComponent(clientPin)}`);

      } else {
        // 📝 GDPR Audit: Failed password operation
        fastify.log.warn({
          event: isNewUser ? 'passwordSetupFailed' : 'passwordVerifyFailed',
          error: ssotData.error,
          gdprCategory: 'authentication'
        });

        return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=` + encodeURIComponent(ssotData.error || 'Password operation failed'));
      }

    } catch (err) {
      // GDPR Audit: System error (network/parse failures only)
      fastify.log.error({
        event: 'secureLoginError',
        error: err.message,
        stack: err.stack,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect(`/secureLogin?clientPin=${clientPin || ''}&error=` + encodeURIComponent('Authentication service unavailable'));
    }
  });
  
  // ==============================================
  // B.4: LOGOUT
  // ==============================================

  fastify.post('/clientsAuth/logout', async (request, reply) => {
    const jwtToken = request.cookies?.qolaeClientToken;
    const clientIP = request.ip;

    // 📝 GDPR Audit Log
    fastify.log.info({
      event: 'clientLogoutRequest',
      hasToken: !!jwtToken,
      ip: clientIP,
      timestamp: new Date().toISOString(),
      gdprCategory: 'authentication'
    });

    // ✅ JWT LOGOUT: Clear cookie (JWT cannot be deleted server-side as it's stateless)
    // NOTE: For enhanced security, implement JWT blacklist in future
    if (jwtToken) {
      try {
        // Log successful JWT logout
        fastify.log.info({
          event: 'jwtCleared',
          gdprCategory: 'authentication'
        });

      } catch (err) {
        fastify.log.error({
          event: 'logoutError',
          error: err.message
        });
      }
    }

    // ✅ Clear the JWT cookie
    reply.header('Set-Cookie', 'qolaeClientToken=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');

    return reply.send({
      success: true,
      redirect: '/clientsLogin'
    });
  });
  
  // ==============================================
  // B.5: SESSION CHECK
  // ==============================================
  
  fastify.get('/clientsAuth/session', async (request, reply) => {
    // No session check needed - authentication handled by SSOT
    return reply.send({
      success: true,
      authenticated: !!request.headers.authorization
    });
  });

  // ==============================================
  // B.6 & B.7: REMOVED - DEAD CODE
  // ==============================================
  // These routes were not being used by any UI:
  // - POST /clients-auth/forgot-password
  // - POST /clients-auth/reset-password-confirm
  //
  // Password reset is handled via:
  // 1. User clicks "Forgot Password?" link
  // 2. Redirects to /secureLogin?clientPin=...&reset=true
  // 3. Form submits to POST /clients-auth/secureLogin
  // 4. Which calls SSOT endpoint /auth/clients/password-reset
  //
  // This maintains the security model: ALL access requires 2FA first.
  // ==============================================

}
