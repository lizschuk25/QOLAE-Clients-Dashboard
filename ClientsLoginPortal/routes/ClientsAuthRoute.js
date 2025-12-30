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
import axios from 'axios';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// A.2: API Configuration
// Configure axios to call the SSOT API
axios.defaults.baseURL = 'https://api.qolae.com';

// ✅ Axios response interceptor for consistent status validation
axios.interceptors.response.use(
  (response) => {
    // Validate successful responses have expected structure
    if (response.status >= 200 && response.status < 300 && response.data === undefined) {
      console.warn('[SSOT] Response missing data payload');
    }
    return response;
  },
  (error) => {
    // Log SSOT errors for debugging
    console.error('[SSOT] API Error:', {
      status: error.response?.status,
      message: error.response?.data?.error || error.message,
      url: error.config?.url
    });
    return Promise.reject(error);
  }
);

// ClientsDashboard baseURL for redirects
const CLIENTS_DASHBOARD_BASE_URL = 'https://clients.qolae.com';

// A.3: JWT Secret - fail fast if not configured
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.error('❌ JWT_SECRET not found in environment variables!');
  throw new Error('JWT_SECRET environment variable is required');
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
  
  fastify.post('/clientsAuth/login', async (request, reply) => {
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
      // ✅ Validate Client PIN format first (using SSOT with userType)
      const pinValidation = await axios.post('/api/pin/validate', {
        pin: clientPin,
        userType: 'client'
      });
      
      if (!pinValidation.data.validation.isValid) {
        fastify.log.warn({
          event: 'invalidPinFormat',
          clientPin: clientPin,
          errors: pinValidation.data.validation.errors
        });

        return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Invalid Client PIN format')}`);
      }
      
      // ✅ Call SSOT API for authentication
      const apiResponse = await axios.post('/auth/clients/requestToken', {
        clientEmail: email,
        clientPin,
        source: 'clients-portal',
        ip: clientIP
      });

      if (apiResponse.data.success) {
        // 📝 GDPR Audit: Successful login
        fastify.log.info({
          event: 'clientLoginSuccess',
          clientPin: clientPin,
          consentSigned: apiResponse.data.client.consentSigned,
          assignedLawyerPin: apiResponse.data.client.assignedLawyerPin
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

          // ✅ SSOT: Validate JWT token (replaces 3 direct DB queries)
          const validationResponse = await axios.post(
            `${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/session/validate`,
            { token: jwtToken }
          );

          if (!validationResponse.data.success || !validationResponse.data.valid) {
            fastify.log.warn({
              event: 'loginInvalidJWT',
              clientPin: clientPin,
              error: validationResponse.data.error || 'Invalid token',
              gdprCategory: 'authentication'
            });
            return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent('Session expired. Please click your PIN link again.')}`);
          }

          // Verify PIN matches JWT payload
          const clientData = validationResponse.data.client;
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
            expiresAt: validationResponse.data.expiresAt,
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
      } else {
        // 📝 GDPR Audit: Failed login
        fastify.log.warn({
          event: 'clientLoginFailed',
          clientPin: clientPin,
          error: apiResponse.data.error
        });

        // ✅ SERVER-SIDE: Redirect back to login with error message
        return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent(apiResponse.data.error || 'Authentication failed')}`);
      }
    } catch (err) {
      // 📝 GDPR Audit: System error
      fastify.log.error({
        event: 'clientLoginError',
        clientPin: clientPin,
        error: err.message,
        stack: err.stack
      });
      
      // Handle API validation errors - redirect with error
      if (err.response?.data?.error) {
        return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin}&error=${encodeURIComponent(err.response.data.error)}`);
      }

      // ✅ SERVER-SIDE: Redirect with system error
      return reply.code(302).redirect(`/clientsLogin?clientPin=${clientPin || ''}&error=${encodeURIComponent('Authentication service unavailable. Please try again.')}`);
    }
  });
  
  // ==============================================
  // B.2: REQUEST EMAIL VERIFICATION CODE (SESSION-BASED)
  // ==============================================
  // ⚠️ REFACTORED: Now uses SSOT endpoint /auth/clients/2fa/request-code

  fastify.post('/clientsAuth/requestEmailCode', async (request, reply) => {
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
      // ✅ STEP 2: Call SSOT endpoint with JWT in Authorization header
      const ssotResponse = await axios.post(
        `${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/2fa/requestCode`,
        {
          ipAddress: clientIP,
          userAgent: request.headers['user-agent']
        },
        {
          headers: {
            'Authorization': `Bearer ${sessionId}`  // ✅ JWT in Authorization header
          }
        }
      );

      const ssotData = ssotResponse.data;

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
      // Handle axios error responses from SSOT
      if (err.response) {
        const status = err.response.status;
        const errorData = err.response.data;

        if (status === 401) {
          fastify.log.warn({
            event: 'verificationCodeRequestInvalidSession',
            error: errorData.error,
            ip: clientIP,
            gdprCategory: 'authentication'
          });

          return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent(errorData.error || 'Session invalid. Please log in again.'));
        }
      }

      // 📝 GDPR Audit: System error
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

  fastify.post('/clientsAuth/verify2fa', async (request, reply) => {
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
      // ✅ STEP 2: Call SSOT endpoint with JWT in Authorization header
      const ssotResponse = await axios.post(
        `${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/2fa/verifyCode`,
        {
          verificationCode: verificationCode,
          ipAddress: clientIP,
          userAgent: request.headers['user-agent']
        },
        {
          headers: {
            'Authorization': `Bearer ${sessionId}`  // ✅ JWT in Authorization header
          }
        }
      );

      const ssotData = ssotResponse.data;

      if (ssotData.success) {
        const clientPin = ssotData.client.clientPin;
        const clientData = ssotData.client;

        // ============================================
        // STEP 3: USE JWT FROM SSOT RESPONSE
        // ============================================
        // ✅ SSOT COMPLIANT: JWT generated & stored by SSOT endpoint
        // No local generation, no direct database access

        const jwtToken = ssotData.accessToken;

        console.log(`🔑 JWT token received from SSOT for Client PIN: ${clientPin}`);

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
      } else {
        // 📝 GDPR Audit: Failed 2FA
        fastify.log.warn({
          event: '2faVerificationFailed',
          error: ssotData.error,
          gdprCategory: 'authentication'
        });

        return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(ssotData.error || '2FA verification failed'));
      }
    } catch (err) {
      // Handle axios error responses from SSOT
      if (err.response) {
        const status = err.response.status;
        const errorData = err.response.data;

        if (status === 401) {
          fastify.log.warn({
            event: '2faVerificationInvalidSession',
            error: errorData.error,
            ip: clientIP,
            gdprCategory: 'authentication'
          });

          // Check if it's a session error or code error
          if (errorData.redirect) {
            return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent(errorData.error || 'Session invalid. Please log in again.'));
          }

          return reply.code(302).redirect('/clients2fa?error=' + encodeURIComponent(errorData.error || 'Invalid verification code'));
        }
      }

      // 📝 GDPR Audit: System error
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

  fastify.post('/clientsAuth/secureLogin', async (request, reply) => {
    const { password, isNewUser } = request.body;
    const clientIP = request.ip;

    // 📝 GDPR Audit Log
    fastify.log.info({
      event: 'secureLoginAttempt',
      isNewUser: isNewUser,
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
      return reply.code(302).redirect('/secureLogin?error=' + encodeURIComponent('Password is required'));
    }

    try {
      // ✅ STEP 2: Determine which SSOT endpoint to call
      const endpoint = isNewUser === 'true' || isNewUser === true
        ? '/auth/clients/passwordSetup'
        : '/auth/clients/passwordVerify';

      console.log(`🔐 Calling SSOT ${endpoint}`);

      // ✅ STEP 3: Call SSOT endpoint with JWT in Authorization header
      const ssotResponse = await axios.post(
        `${process.env.API_BASE_URL || 'https://api.qolae.com'}${endpoint}`,
        {
          password: password,
          ipAddress: clientIP,
          userAgent: request.headers['user-agent']
        },
        {
          headers: {
            'Authorization': `Bearer ${jwtToken}`  // ✅ JWT in Authorization header
          }
        }
      );

      const ssotData = ssotResponse.data;

      if (ssotData.success) {
        // ============================================
        // STEP 4: UPDATE COOKIE WITH NEW JWT (if provided)
        // ============================================
        if (ssotData.accessToken) {
          reply.setCookie('qolaeClientToken', ssotData.accessToken, {
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 24  // 24 hours
          });

          console.log(`🔑 Updated JWT cookie after password ${isNewUser ? 'setup' : 'verify'}`);
        }

        // 📝 GDPR Audit: Successful password operation
        fastify.log.info({
          event: isNewUser ? 'passwordSetupSuccess' : 'passwordVerifySuccess',
          clientPin: ssotData.client?.clientPin,
          gdprCategory: 'authentication'
        });

        // ✅ STEP 5: Redirect to Dashboard with Client PIN parameter
        const clientPin = ssotData.client?.clientPin;
        if (!clientPin) {
          return reply.code(302).redirect('/secureLogin?error=' + encodeURIComponent('Session data incomplete'));
        }
        return reply.code(302).redirect(`/ClientsDashboard?clientPin=${encodeURIComponent(clientPin)}`);

      } else {
        // 📝 GDPR Audit: Failed password operation
        fastify.log.warn({
          event: isNewUser ? 'passwordSetupFailed' : 'passwordVerifyFailed',
          error: ssotData.error,
          gdprCategory: 'authentication'
        });

        return reply.code(302).redirect('/secureLogin?error=' + encodeURIComponent(ssotData.error || 'Password operation failed'));
      }

    } catch (err) {
      // Handle axios error responses from SSOT
      if (err.response) {
        const status = err.response.status;
        const errorData = err.response.data;

        if (status === 401) {
          fastify.log.warn({
            event: 'secureLoginInvalidSession',
            error: errorData.error,
            ip: clientIP,
            gdprCategory: 'authentication'
          });

          return reply.code(302).redirect('/clientsLogin?error=' + encodeURIComponent('Session expired. Please click your PIN link again.'));
        }

        if (status === 409) {
          // Password already set up - redirect to verify instead
          return reply.code(302).redirect('/secureLogin?setupCompleted=true&error=' + encodeURIComponent('Password already set up. Please enter your password.'));
        }
      }

      // 📝 GDPR Audit: System error
      fastify.log.error({
        event: 'secureLoginError',
        error: err.message,
        stack: err.stack,
        gdprCategory: 'authentication'
      });

      return reply.code(302).redirect('/secureLogin?error=' + encodeURIComponent('Authentication service unavailable'));
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
