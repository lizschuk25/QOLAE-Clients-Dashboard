// ==============================================
// QOLAE CLIENTS DASHBOARD SERVER
// ==============================================
// Purpose: Secure workspace for clients to manage INA consent, appointments, and reports
// Author: Liz
// Date: 28th October 2025
// Port: 3010
// PM2 Process: qolae-clients
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
dotenv.config({ path: path.join(process.cwd(), '..', '.env') });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==============================================
// FASTIFY SERVER INITIALIZATION
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
// MIDDLEWARE REGISTRATION
// ==============================================

// 1. CORS Configuration
await server.register(fastifyCors, {
  origin: process.env.CORS_ORIGIN || 'https://clients.qolae.com',
  credentials: true,
});

// 2. JWT Authentication
await server.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'clients-secret-key-2025',
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
    fileSize: 10 * 1024 * 1024, // 10MB max file size
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
// ROUTES REGISTRATION
// ==============================================

// Authentication Routes (PIN-based from HR Compliance)
await server.register(import('./routes/authRoutes.js'));

// Client Routes (Consent, Appointments, Documents, Reports)
await server.register(import('./routes/clientRoutes.js'));

// ==============================================
// ROOT ROUTE
// ==============================================

server.get('/', async (request, reply) => {
  return reply.redirect('/clients-login');
});

// ==============================================
// HEALTH CHECK
// ==============================================

server.get('/health', async (request, reply) => {
  return {
    status: 'healthy',
    service: 'qolae-clients-dashboard',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    database: 'qolae_hrcompliance', // Client data lives in HR Compliance DB
  };
});

// ==============================================
// ERROR HANDLING
// ==============================================

server.setErrorHandler((error, request, reply) => {
  server.log.error(error);

  // Send appropriate error response
  reply.status(error.statusCode || 500).send({
    success: false,
    error: error.message || 'Internal Server Error',
    timestamp: new Date().toISOString(),
  });
});

// ==============================================
// SERVER START
// ==============================================

const start = async () => {
  try {
    const port = process.env.CLIENTS_PORT || 3010;
    const host = process.env.HOST || '0.0.0.0';

    await server.listen({ port, host });

    console.log('');
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║   👤 QOLAE CLIENTS DASHBOARD STARTED           ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log('');
    console.log(`📍 Server running at: http://${host}:${port}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 Database: qolae_hrcompliance (Clients data)`);
    console.log(`🔌 WebSocket: Port 3011 (qolae-wsclients)`);
    console.log('');
    console.log('Available Routes:');
    console.log('  🔐 Login: /clients-login');
    console.log('  🏠 Dashboard: /clients-dashboard');
    console.log('  📝 Consent Form: /consent/*');
    console.log('  📅 Appointments: /appointment/*');
    console.log('  📂 Documents: /documents');
    console.log('  📄 Report: /report/*');
    console.log('  🆘 Support: /support/*');
    console.log('  ❤️ Health Check: /health');
    console.log('');
    console.log('Ready for clients to access their secure portal! 🚀');
    console.log('');

  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

// Start the server
start();

export default server;

