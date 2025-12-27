// ==============================================
// QOLAE CLIENTS DASHBOARD SERVER
// ==============================================
// Purpose: Secure workspace for clients - consent, documents, reports
// Author: Liz
// Date: 27th December 2025
// Port: 3010
// PM2 Process: qolae-clients
// Architecture: SSOT - Calls api.qolae.com for data
// Database: qolae_clients (via API-Dashboard SSOT)
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import Fastify from 'fastify';
import path from 'path';
import { fileURLToPath } from 'url';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import ejs from 'ejs';
import fastifyFormbody from '@fastify/formbody';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyMultipart from '@fastify/multipart';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==============================================
// LOCATION BLOCK B: FASTIFY SERVER INITIALIZATION
// ==============================================
const server = Fastify({
    logger: {
        level: 'info',
        transport: {
            target: 'pino-pretty',
            options: {
                translateTime: 'HH:MM:ss Z',
                ignore: 'pid,hostname',
            },
        },
    },
});

// ==============================================
// LOCATION BLOCK C: MIDDLEWARE REGISTRATION
// ==============================================

// 1. CORS Configuration
await server.register(fastifyCors, {
    origin: process.env.CORS_ORIGIN || 'https://clients.qolae.com',
    credentials: true,
});

// 2. JWT Authentication (must match LoginPortal secret)
await server.register(fastifyJwt, {
    secret: process.env.JWT_SECRET || 'clients-jwt-secret-production-2025',
    cookie: {
        cookieName: 'qolaeClientToken',
        signed: false,
    },
});

// 3. Cookie Support
await server.register(fastifyCookie);

// 4. Form Body Parser
await server.register(fastifyFormbody);

// 5. Multipart (for signature uploads)
await server.register(fastifyMultipart, {
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB max
    },
});

// 6. Static Files
await server.register(fastifyStatic, {
    root: path.join(__dirname, 'public'),
    prefix: '/public/',
});

// 7. View Engine (EJS)
await server.register(fastifyView, {
    engine: {
        ejs: ejs,
    },
    root: path.join(__dirname, 'views'),
    options: {
        filename: path.join(__dirname, 'views'),
    },
});

// ==============================================
// LOCATION BLOCK D: AUTHENTICATION DECORATOR
// ==============================================
/**
 * Decorator to verify client JWT and attach user data
 */
server.decorate('authenticateClient', async function(request, reply) {
    try {
        await request.jwtVerify();
        
        if (request.user.role !== 'client') {
            throw new Error('Invalid role');
        }
    } catch (error) {
        // Redirect to LoginPortal
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clients-login';
        return reply.redirect(`${loginUrl}?error=Session expired. Please login again.`);
    }
});

// ==============================================
// LOCATION BLOCK E: ROUTES REGISTRATION
// ==============================================

// Client Workflow Routes (SSOT compliant - calls API for data)
await server.register(import('./routes/clientWorkflowRoutes.js'));

// ==============================================
// LOCATION BLOCK F: ROOT ROUTE
// ==============================================
server.get('/', async (request, reply) => {
    // Check if authenticated
    try {
        await request.jwtVerify();
        return reply.redirect('/clients-dashboard');
    } catch (error) {
        // Not authenticated, redirect to LoginPortal
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clients-login';
        return reply.redirect(loginUrl);
    }
});

// ==============================================
// LOCATION BLOCK G: HEALTH CHECK
// ==============================================
server.get('/health', async (request, reply) => {
    return {
        status: 'healthy',
        service: 'qolae-clients-dashboard',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'production',
        architecture: 'SSOT via API-Dashboard',
        database: 'qolae_clients (via api.qolae.com)',
    };
});

// ==============================================
// LOCATION BLOCK H: ERROR HANDLING
// ==============================================
server.setErrorHandler((error, request, reply) => {
    server.log.error(error);

    // Check if it's an auth error
    if (error.statusCode === 401) {
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clients-login';
        return reply.redirect(`${loginUrl}?error=Please login to continue.`);
    }

    reply.status(error.statusCode || 500).send({
        success: false,
        error: error.message || 'Internal Server Error',
        timestamp: new Date().toISOString(),
    });
});

// ==============================================
// LOCATION BLOCK I: SERVER START
// ==============================================
const start = async () => {
    try {
        const port = process.env.CLIENTS_DASHBOARD_PORT || 3010;
        const host = process.env.HOST || '0.0.0.0';

        await server.listen({ port, host });

        console.log('');
        console.log('╔══════════════════════════════════════════════════╗');
        console.log('║   👤 QOLAE CLIENTS DASHBOARD STARTED             ║');
        console.log('╚══════════════════════════════════════════════════╝');
        console.log('');
        console.log(`📍 Server running at: http://${host}:${port}`);
        console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
        console.log(`🔐 Auth: JWT via LoginPortal (Port 3014)`);
        console.log(`🗄️  Database: qolae_lawyers (consentForms table)`);
        console.log(`📡 WebSocket: Port 3011 (qolae-wsclients)`);
        console.log('');
        console.log('Available Routes:');
        console.log('  🏠 Dashboard:     /clients-dashboard');
        console.log('  📝 Consent:       /consent/*');
        console.log('  📅 Appointments:  /appointment/*');
        console.log('  📁 Documents:     /documents/*');
        console.log('  📊 Report:        /report/*');
        console.log('  🔔 Notifications: /api/notifications/*');
        console.log('  ❤️  Health:        /health');
        console.log('');
        console.log('🔐 All routes require authentication via LoginPortal');
        console.log('');

    } catch (err) {
        server.log.error(err);
        process.exit(1);
    }
};

// Start the server
start();

export default server;