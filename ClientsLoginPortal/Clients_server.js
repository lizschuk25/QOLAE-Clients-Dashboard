// ==============================================
// QOLAE CLIENTS LOGIN PORTAL SERVER
// ==============================================
// Purpose: 2FA authentication for clients (PIN + Email verification)
// Author: Liz
// Date: 26th December 2025
// Port: 3014
// PM2 Process: qolae-clients-login
// Database: qolae_lawyers (consentForms table)
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import Fastify from 'fastify';
import path from 'path';
import { fileURLToPath } from 'url';
import fastifyView from '@fastify/view';
import ejs from 'ejs';
import fastifyFormbody from '@fastify/formbody';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
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

// 2. JWT Authentication
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

// 5. View Engine (EJS)
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
// LOCATION BLOCK D: ROUTES REGISTRATION
// ==============================================

// Authentication Routes (PIN + 2FA)
await server.register(import('./routes/clientsAuthRoute.js'));

// ==============================================
// LOCATION BLOCK E: ROOT ROUTE
// ==============================================
server.get('/', async (request, reply) => {
    return reply.redirect('/clients-login');
});

// ==============================================
// LOCATION BLOCK F: HEALTH CHECK
// ==============================================
server.get('/health', async (request, reply) => {
    return {
        status: 'healthy',
        service: 'qolae-clients-login-portal',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'production',
        database: 'qolae_lawyers (consentForms table)',
    };
});

// ==============================================
// LOCATION BLOCK G: ERROR HANDLING
// ==============================================
server.setErrorHandler((error, request, reply) => {
    server.log.error(error);

    reply.status(error.statusCode || 500).send({
        success: false,
        error: error.message || 'Internal Server Error',
        timestamp: new Date().toISOString(),
    });
});

// ==============================================
// LOCATION BLOCK H: SERVER START
// ==============================================
const start = async () => {
    try {
        const port = process.env.CLIENTS_LOGIN_PORT || 3014;
        const host = process.env.HOST || '0.0.0.0';

        await server.listen({ port, host });

        console.log('');
        console.log('╔══════════════════════════════════════════════════╗');
        console.log('║   🔐 QOLAE CLIENTS LOGIN PORTAL STARTED          ║');
        console.log('╚══════════════════════════════════════════════════╝');
        console.log('');
        console.log(`📍 Server running at: http://${host}:${port}`);
        console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
        console.log(`🔒 Cookies: Secure (HTTPS only)`);
        console.log(`🗄️  Database: qolae_lawyers (consentForms table)`);
        console.log('');
        console.log('Available Routes:');
        console.log('  🔑 Login:     /clients-login');
        console.log('  📧 2FA:       /clients-2fa');
        console.log('  ✅ Verify:    /api/clients/verify-email-code');
        console.log('  🚪 Logout:    /api/clients/logout');
        console.log('  ❤️  Health:    /health');
        console.log('');
        console.log('➡️  On success, redirects to Dashboard (Port 3010)');
        console.log('');

    } catch (err) {
        server.log.error(err);
        process.exit(1);
    }
};

// Start the server
start();

export default server;