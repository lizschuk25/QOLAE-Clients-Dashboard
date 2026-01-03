// ==============================================
// Clients_server.js - Clients Login Portal Server
// QOLAE Clients Login & Authentication Hub
// THE BRIDGE: Between Admin-Dashboard and Clients-Dashboard
// Organized by Location Block Workflow Pattern
// Author: Liz 👑
// Port: 3014
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// A.1: Core Dependencies & ES6 Setup
// A.2: Environment Variables
// A.3: Server Initialization
// ==============================================

// A.1: Core Dependencies & ES6 Setup
import Fastify from 'fastify';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import axios from 'axios';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import fastifyView from '@fastify/view';
import cookie from '@fastify/cookie';
import ejs from 'ejs';

// Import session middleware
import sessionMiddleware, { createSession, SESSION_CONFIG } from './middleware/sessionManager.js';

// ES6 module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// A.2: Environment Variables
dotenv.config({ path: `${__dirname}/.env` });

// A.3: Server Initialization
const fastify = Fastify({ logger: true });

// ==============================================
// LOCATION BLOCK B: MIDDLEWARE & PLUGINS
// B.1: CORS Configuration
// B.2: Cache-Busting Headers
// B.3: Form Body Parser
// B.4: Static File Serving
// B.5: View Engine Setup
// ==============================================

// B.1: CORS Configuration
fastify.register(cors, {
  origin: [
    'https://admin.qolae.com',
    'https://api.qolae.com',
    'https://lawyers.qolae.com',
    'https://clients.qolae.com',
    'https://hrcompliance.qolae.com',
    'https://casemanagers.qolae.com',
    'https://readers.qolae.com',
  ],
  methods: ['GET', 'POST'],
  credentials: true
});

// B.2: Cache-Busting Middleware - Prevent stale content
fastify.addHook('onRequest', async (request, reply) => {
  reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  reply.header('Pragma', 'no-cache');
  reply.header('Expires', '0');
  reply.header('Last-Modified', new Date().toUTCString());
  reply.header('ETag', `"${Date.now()}"`);
});

// B.3: Form Body Parser
fastify.register(formbody);

// B.3.1: Cookie Parser
fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET || process.env.CLIENTS_LOGIN_JWT_SECRET,
  parseOptions: {}
});

  // B.4: Static File Serving (GDPR compliant)
  const staticRoots = [path.join(__dirname, 'public')];
  const staticPrefixes = ['/public/'];
  
  if (process.env.CENTRAL_REPOSITORY_PATH) {
    staticRoots.push(process.env.CENTRAL_REPOSITORY_PATH);
    staticPrefixes.push('/centralRepository/');
  }
  
  fastify.register(await import('@fastify/static'), {
    root: staticRoots,
    prefix: staticPrefixes
  });

// B.5: View Engine Setup
fastify.register(fastifyView, {
  engine: {
    ejs: ejs
  },
  root: path.join(__dirname, 'views')
});

// B.6: Session Middleware (HTTP-only cookie management)
fastify.register(sessionMiddleware);

// ==============================================
// LOCATION BLOCK C: AUTHENTICATION SETUP
// C.1: JWT Configuration
// C.2: In-Memory Store (Development)
// C.3: JWT Verification Middleware
// C.4: Security Helper Functions
// C.5: PIN Token Management
// C.6: Session Management
// C.7: Security Audit Logging
// ==============================================

// C.1: JWT Secret
const JWT_SECRET = process.env.CLIENTS_LOGIN_JWT_SECRET;

// C.2: In-memory store for client credentials (replace with database in production)
const clientCredentials = new Map();

// C.3: Middleware to verify JWT token
const authenticateToken = async (request, reply) => {
  const authHeader = request.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return reply.code(401).send({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    request.user = decoded;
  } catch (err) {
    return reply.code(403).send({ error: 'Invalid token' });
  }
};

// C.4: Security Helper Functions
import crypto from 'crypto';

function generateSecureToken() {
  return crypto.randomBytes(8).toString('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateDeviceFingerprint(req) {
  const components = [
    req.headers['user-agent'],
    req.headers['accept-language'],
    req.headers['accept-encoding']
  ].join('|');

  return crypto.createHash('sha256').update(components).digest('hex');
}

// C.5: [REMOVED - Dead Code] generatePinToken() deleted - now handled by SSOT /auth/clients/pinAccess

// C.6: [REMOVED - Dead Code] createClientSession() deleted - now handled by SSOT /auth/clients/pinAccess

// C.7: [REMOVED - Dead Code] logSecurityEvent() deleted - was only called by dead functions above
// Note: Security logging in secure-login route uses direct INSERT - kept as legitimate local concern

// ==============================================
// LOCATION BLOCK 1: CORE ROUTING
// 1.1: Root & Redirect Routes
// 1.2: Login Page Routes
// 1.3: 2FA Authentication Route
// 1.4: Dashboard & Logout Routes
// ==============================================

// 1.1: Root Route - Redirect to Login
fastify.get('/', async (request, reply) => {
  return reply.redirect('/clientsLogin');
});

// 1.2a: Clients Login Page - Main Route with PIN Access via SSOT - ENHANCED WITH SECURITY
fastify.get('/clientsLogin', async (request, reply) => {
  const { clientPin } = request.query;
  const clientIP = request.ip;
  const userAgent = request.headers['user-agent'];

  // ═══════════════════════════════════════════════════════════
  // SCENARIO A: NO PIN = Show Login Form (Logout/Direct Access)
  // User must enter Client PIN + Email to start 2FA authentication flow
  // ═══════════════════════════════════════════════════════════
  if (!clientPin) {
    return reply.view('clientsLogin.ejs', {
      title: 'QOLAE Clients Login',
      error: request.query.error || null,
      success: request.query.success || null,
      message: 'Please enter your Client PIN and email address to log in'
    });
  }

  // ═══════════════════════════════════════════════════════════
  // SCENARIO B: HAS PIN = Email Hyperlink Flow
  // ⚠️ REFACTORED: Now uses SSOT endpoint /auth/clients/pinAccess
  // This starts the 2FA authentication + secure-login process
  // Even with PIN, users MUST complete full authentication
  // NO shortcuts to dashboard - GDPR Article 9 compliance
  // ═══════════════════════════════════════════════════════════

  try {
    console.log(`🔒 [SSOT] PIN Access request for: ${clientPin}`);

    // ============================================
    // STEP 1: CALL SSOT ENDPOINT (replaces 7 violations)
    // ============================================
    const deviceFingerprint = generateDeviceFingerprint(request);

    const ssotResponse = await axios.post(`${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/pinAccess`, {
      clientPin: clientPin,
      deviceFingerprint: deviceFingerprint,
      ipAddress: clientIP,
      userAgent: userAgent
    });

    const ssotData = ssotResponse.data;

    if (!ssotData.success) {
      console.log(`[SSOT] PIN Access failed: ${ssotData.error}`);
      return reply.code(401).send('Invalid Client PIN');
    }

    console.log(`[SSOT] PIN Access successful for: ${clientPin}, isNew: ${ssotData.isNewClient}`);

    // ============================================
    // STEP 2: STORE IN REQUEST SESSION
    // ============================================

    // Initialize session if it doesn't exist
    if (!request.session) {
      request.session = {};
    }

    request.session.client = {
      clientPin: ssotData.client.clientPin,
      email: ssotData.client.email,
      name: ssotData.client.clientName,
      accessToken: ssotData.token,  // ✅ JWT token
      tokenStatus: 'active',
      jwtToken: ssotData.token,      // ✅ JWT token
      deviceFingerprint: deviceFingerprint,
      isFirstAccess: ssotData.isNewClient,
      authenticated2FA: false,
      authenticatedPassword: false
    };

    // ============================================
    // STEP 3: SET HTTP-ONLY COOKIE & RENDER LOGIN PAGE
    // ============================================

    // Set HTTP-only JWT cookie
    reply.setCookie('qolaeClientToken', ssotData.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: ssotData.expiresIn * 1000, // ✅ Use expiry from SSOT (5 hours in ms)
      path: '/',
      domain: process.env.COOKIE_DOMAIN || '.qolae.com'
    });

    return reply.view('clientsLogin.ejs', {
      title: 'QOLAE Clients Login',
      clientPin: ssotData.client.clientPin,
      email: ssotData.client.email,
      clientName: ssotData.client.clientName,
      isFirstAccess: ssotData.isNewClient,
      tokenStatus: 'active',
      error: request.query.error || null,
      success: request.query.success || null
    });

  } catch (error) {
    console.error('❌ [SSOT] ClientsLogin error:', error.message);

    // Handle axios error responses
    if (error.response) {
      const status = error.response.status;
      const errorData = error.response.data;

      if (status === 401) {
        return reply.code(404).send('Invalid Client PIN');
      }
      if (status === 403) {
        return reply.code(403).send(`
          <h2>Access Revoked</h2>
          <p>Your access has been revoked. Contact support@qolae.com</p>
        `);
      }
    }

    return reply.code(500).send('Internal server error');
  }
});

// 1.2b: Backward compatibility redirect
fastify.get('/login', async (request, reply) => {
  const { clientPin } = request.query;
  const redirectUrl = clientPin ? `/clientsLogin?clientPin=${clientPin}` : '/clientsLogin';
  return reply.redirect(redirectUrl);
});

// 1.3: 2FA Authentication Page
// ✅ SSOT COMPLIANT - Uses /session/validate + /check-password-status
fastify.get('/clients2fa', async (request, reply) => {
  // Read JWT token from HTTP-only cookie
  const sessionId = request.cookies.qolaeClientToken;

  if (!sessionId) {
    return reply.view('clients2fa.ejs', {
      title: '2-Way Authentication - QOLAE Clients Portal',
      error: 'No active session. Please return to login.',
      clientPin: null,
      email: null,
      clientName: null,
      authToken: null,
      query: request.query  // ✅ FIX: Added missing query
    });
  }

  try {
    // ============================================
    // STEP 1: Validate session via SSOT
    // ============================================
    const sessionResponse = await axios.post(
      `${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/session/validate`,
      { token: sessionId }  // ✅ Changed from sessionToken to token
    );

    if (!sessionResponse.data.success) {
      return reply.view('clients2fa.ejs', {
        title: '2-Way Authentication - QOLAE Clients Portal',
        error: sessionResponse.data.error || 'Session invalid. Please return to login.',
        clientPin: null,
        email: null,
        clientName: null,
        authToken: null,
        query: request.query  // ✅ FIX: Added missing query
      });
    }

    // ✅ FIX: SSOT returns 'client', not 'session'
    const client = sessionResponse.data.client;

    fastify.log.info('2FA Session Data:', {
      clientPin: client.clientPin,
      email: client.email,
      sessionId: sessionId
    });

    return reply.view('clients2fa.ejs', {
      title: '2-Way Authentication - QOLAE Clients Portal',
      clientPin: client.clientPin,
      email: client.email,
      clientName: client.clientName,
      authToken: sessionId,
      query: request.query  // ✅ Pass query params for server-side modal control
    });

  } catch (error) {
    fastify.log.error('2FA page error:', error.message);

    // Handle axios error responses
    if (error.response?.status === 401) {
      return reply.view('clients2fa.ejs', {
        title: '2-Way Authentication - QOLAE Clients Portal',
        error: 'Session expired. Please return to login.',
        clientPin: null,
        email: null,
        clientName: null,
        authToken: null,
        query: request.query  // ✅ FIX: Added missing query
      });
    }

    return reply.view('clients2fa.ejs', {
      title: '2-Way Authentication - QOLAE Clients Portal',
      error: 'An error occurred. Please return to login.',
      clientPin: null,
      email: null,
      clientName: null,
      authToken: null,
      query: request.query  // ✅ FIX: Added missing query
    });
  }
});

// 1.4a: Clients Dashboard (protected route)
fastify.get('/clientsDashboard', { preHandler: authenticateToken }, async (request, reply) => {
  return reply.redirect('/clientsLogin?token=' + encodeURIComponent(request.user.token));
});

// 1.4a: Secure Login (Password Setup)
// ✅ SSOT COMPLIANT - Uses GET /auth/clients/loginStatus
fastify.get('/secureLogin', async (req, reply) => {
  const { verified, clientPin } = req.query;
  const token = req.cookies.qolaeClientToken;

  reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  reply.header('Pragma', 'no-cache');
  reply.header('Expires', '0');

  if (!clientPin) {
    return reply.code(400).send('Client PIN required');
  }

  // Check for JWT token (set at PIN access stage)
  if (!token) {
    console.log('[SecureLogin] No JWT token found, redirecting to login');
    return reply.redirect(`/clientsLogin?clientPin=${clientPin}&error=sessionExpired`);
  }

  try {
    // ============================================
    // STEP 1: CALL SSOT API FOR CLIENT STATUS
    // ============================================

    const statusResponse = await axios.get(
      `${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/loginStatus`,
      {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      }
    );

    if (!statusResponse.data.success) {
      console.log('[SecureLogin] SSOT status check failed:', statusResponse.data.error);
      return reply.redirect(`/clientsLogin?clientPin=${clientPin}&error=statusCheckFailed`);
    }

    const client = statusResponse.data.client;
    console.log(`[SecureLogin] SSOT status retrieved for: ${client.clientPin}`);

    // ============================================
    // STEP 2: DETERMINE USER STATUS
    // ============================================

    const userStatus = {
      isFirstTime: !client.passwordSetupCompleted,
      hasPassword: client.hasPassword,
      tokenStatus: client.pinAccessTokenStatus
    };

    // ============================================
    // STEP 3: CALCULATE SETUP PROGRESS
    // (Derived from clients table - no clientSetupProgress dependency)
    // ============================================

    const progressSteps = [
      { key: 'linkClicked', label: 'Email Link Clicked', completed: true },  // They're here = link clicked
      { key: '2faVerified', label: '2FA Verification', completed: userStatus.hasPassword || userStatus.tokenStatus === 'active' },
      { key: 'passwordCreated', label: 'Password Setup', completed: userStatus.hasPassword },
      { key: 'workspaceAccess', label: 'Workspace Access', completed: userStatus.tokenStatus === 'active' }
    ];

    const completedSteps = progressSteps.filter(step => step.completed).length;
    const progressPercentage = Math.round((completedSteps / progressSteps.length) * 100);

    // ============================================
    // STEP 4: DETERMINE UI STATE
    // ============================================

    let uiState = 'unknown';
    let welcomeMessage = '';
    let actionRequired = '';

    // Check if this is a password reset request
    const isPasswordReset = req.query.reset === 'true' || req.query.forgot === 'true';

    if (isPasswordReset) {
      uiState = 'forgotPassword';
      welcomeMessage = `Reset Your Password`;
      actionRequired = 'Enter your email to receive a password reset link';
    } else if (userStatus.isFirstTime && !userStatus.hasPassword) {
      uiState = 'firstTimeSetup';
      welcomeMessage = `Welcome ${client.clientName}! Let's set up your secure workspace.`;
      actionRequired = 'Create your password to activate access';
    } else if (userStatus.hasPassword && userStatus.tokenStatus === 'pending') {
      uiState = 'passwordRequired';
      welcomeMessage = `Welcome back ${client.clientName}! Complete your setup.`;
      actionRequired = 'Create your password to activate access';
    } else if (userStatus.hasPassword && userStatus.tokenStatus === 'active') {
      uiState = 'returningUser';
      welcomeMessage = `Welcome back ${client.clientName}!`;
      actionRequired = 'Enter your password to access your workspace';
    } else if (userStatus.tokenStatus === 'revoked') {
      uiState = 'accessRevoked';
      welcomeMessage = `Access Revoked`;
      actionRequired = 'Contact support@qolae.com for assistance';
    }

    // ============================================
    // STEP 5: SECURITY LOGGING (SSOT COMPLIANT)
    // ============================================

    await axios.post(`${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/securityLog`, {
      clientPin: clientPin,
      eventType: 'secureLoginPageAccessed',
      eventStatus: 'success',
      details: {
        uiState: uiState,
        progressPercentage: progressPercentage,
        completedSteps: completedSteps,
        isPasswordReset: isPasswordReset,
        source: 'ClientsLoginPortal'
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      riskScore: 0
    }).catch(err => console.log('[SecureLogin] Security log failed (non-blocking):', err.message));

    // ============================================
    // STEP 6: RENDER WITH SMART DATA
    // ============================================

    return reply.view('secureLogin.ejs', {
      title: 'Secure Login - QOLAE Clients Portal',
      verified: verified || false,
      clientPin: clientPin,

      // State for form rendering
      state: isPasswordReset ? 'resetPassword' : (userStatus.isFirstTime ? 'createPassword' : 'loginPassword'),

      // Smart User Detection Data
      userStatus: userStatus,
      uiState: uiState,
      welcomeMessage: welcomeMessage,
      actionRequired: actionRequired,
      progressSteps: progressSteps,
      progressPercentage: progressPercentage,
      completedSteps: completedSteps,

      // Client Information
      clientName: client.clientName,
      clientEmail: client.clientEmail,

      // Security Status
      tokenStatus: userStatus.tokenStatus,
      isFirstTime: userStatus.isFirstTime,
      hasPassword: userStatus.hasPassword,

      // ✅ SERVER-SIDE: Query params for error/success messages
      query: req.query
    });

  } catch (error) {
    console.error('❌ SecureLogin SSOT error:', error.message);

    // Log error via SSOT endpoint (non-blocking)
    await axios.post(`${process.env.API_BASE_URL || 'https://api.qolae.com'}/auth/clients/securityLog`, {
      clientPin: clientPin,
      eventType: 'secureLoginError',
      eventStatus: 'failure',
      details: { error: error.message, source: 'ClientsLoginPortal' },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      riskScore: 30
    }).catch(err => console.log('[SecureLogin] Error log failed (non-blocking):', err.message));

    return reply.redirect(`/clientsLogin?clientPin=${clientPin}&error=secureLoginFailed`);
  }
});

// ============================================
// NOTE: POST /clientsAuth/secureLogin route moved to clientsAuthRoute.js
// This route is now handled by the SSOT-compliant version in routes/clientsAuthRoute.js
// Date: 29th December 2025
// Reason: Eliminate duplicate route registration and ensure proper SSOT architecture
// ============================================

// 1.4b: Logout
fastify.post('/logout', async (request, reply) => {
  return reply.send({
    success: true,
    message: 'Logged out successfully',
    redirect: '/clientsLogin'
  });
});

// ==============================================
// LOCATION BLOCK 2: HELPER FUNCTIONS
// 2.1: Client System Validation
// ==============================================

// 2.1: Helper function to check client in system (via SSOT API)
const checkClientInSystem = async (clientPin) => {
  try {
    const response = await axios.get(`/api/client/validate/${clientPin}`);
    const result = response.data;

    if (result.success && result.client) {
      fastify.log.info(`✅ Client found via API: ${result.client.clientName} (${result.client.clientPin})`);
      return {
        clientPin: result.client.clientPin,
        email: result.client.email,
        clientName: result.client.clientName
      };
    } else {
      fastify.log.warn(`❌ Client not found via API: ${clientPin}`);
      return null;
    }
  } catch (error) {
    fastify.log.error('Error checking client via API:', error);
    return null;
  }
};

// Make checkClientInSystem available to routes
fastify.decorate('checkClientInSystem', checkClientInSystem);

// ==============================================
// LOCATION BLOCK 3: EXTERNAL ROUTE MODULES
// 3.1: Register Authentication Routes
// ==============================================

// 3.1: Register external route modules
// NOTE: clientsAuthRoute will be imported dynamically in start() function
// to ensure dotenv.config() has been called first

// ==============================================
// LOCATION BLOCK 4: SERVER STARTUP
// 4.1: Start Server & Listen
// ==============================================

// 4.1: Start Server
const start = async () => {
  try {
    // Import and register clientsAuthRoute AFTER dotenv.config()
    const { default: clientsAuthRoute } = await import('./routes/clientsAuthRoute.js');
    await fastify.register(clientsAuthRoute);

    await fastify.listen({
      port: process.env.PORT || 3014,
      host: '0.0.0.0'
    });
    const address = fastify.server.address();
    console.log(`🚀 ClientsLoginPortal bound to: ${address.address}:${address.port}`);
    fastify.log.info(`Clients Login Portal running on port ${fastify.server.address().port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();