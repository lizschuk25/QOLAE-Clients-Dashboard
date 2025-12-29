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
// LOCATION BLOCK D: CONSTANTS & CONFIGURATION
// ==============================================
const SSOT_BASE_URL = process.env.API_BASE_URL || 'https://api.qolae.com';

// ==============================================
// LOCATION BLOCK E: AUTHENTICATION DECORATOR
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
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(`${loginUrl}?error=Session expired. Please login again.`);
    }
});

// ==============================================
// LOCATION BLOCK F: BOOTSTRAP HELPER FUNCTION
// ==============================================
/**
 * Builds client bootstrap data from SSOT API
 * @param {string} clientPin - Client PIN identifier
 * @returns {Promise<Object|null>} Bootstrap data or null if error
 */
async function buildClientBootstrapData(clientPin) {
    try {
        console.log(`📊 [ClientsDashboard] Building bootstrap data for Client PIN: ${clientPin}`);

        // Get stored JWT token from SSOT
        const tokenResponse = await fetch(`${SSOT_BASE_URL}/auth/clients/getStoredToken?clientPin=${clientPin}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!tokenResponse.ok) {
            console.warn(`⚠️ [ClientsDashboard] No valid JWT token found for Client PIN: ${clientPin}`);
            return null;
        }

        const tokenData = await tokenResponse.json();
        const { accessToken } = tokenData;

        // Call SSOT bootstrap endpoint with stored JWT token
        const bootstrapResponse = await fetch(`${SSOT_BASE_URL}/clients/workspace/bootstrap`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (bootstrapResponse.ok) {
            const bootstrapData = await bootstrapResponse.json();
            console.log(`✅ [ClientsDashboard] Bootstrap data fetched successfully for ${clientPin}`);
            return bootstrapData;
        } else {
            console.error(`❌ [ClientsDashboard] SSOT bootstrap failed:`, bootstrapResponse.status);
            return null;
        }

    } catch (error) {
        console.error(`❌ [ClientsDashboard] Bootstrap error for ${clientPin}:`, error.message);
        return null;
    }
}

// ==============================================
// LOCATION BLOCK G: MAIN DASHBOARD ROUTE
// ==============================================
/**
 * Main Clients Dashboard Route
 * Uses SSOT Bootstrap as SINGLE SOURCE OF TRUTH
 * No duplicate database queries - all data comes from SSOT
 */
server.get('/ClientsDashboard', async (req, reply) => {
    reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    reply.header('Pragma', 'no-cache');
    reply.header('Expires', '0');

    const { clientPin } = req.query;

    if (!clientPin) {
        return reply.code(400).send({ error: 'Client PIN required' });
    }

    try {
        console.log(`🔍 [ClientsDashboard] Dashboard route called with Client PIN: ${clientPin}`);

        // SINGLE SOURCE OF TRUTH - SSOT Bootstrap only
        const bootstrapData = await buildClientBootstrapData(clientPin);

        if (!bootstrapData || !bootstrapData.valid) {
            console.error(`❌ Invalid bootstrap for Client PIN: ${clientPin}`);
            return reply.code(401).send({ error: 'Invalid session - please login again' });
        }

        console.log(`✅ Dashboard loading for ${bootstrapData.user.clientName} (${clientPin})`);

        // ==========================================
        // SERVER-SIDE DATA TRANSFORMATION
        // Transform bootstrap data into template-ready structures
        // ==========================================

        // 1. CLIENT object (template expects firstName, name)
        const clientNameParts = (bootstrapData.user.clientName || 'Client User').split(' ');
        const client = {
            clientPin: bootstrapData.user.clientPin,
            firstName: clientNameParts[0],
            name: bootstrapData.user.clientName,
            clientName: bootstrapData.user.clientName,
            clientEmail: bootstrapData.user.clientEmail,
            assignedLawyerPin: bootstrapData.user.assignedLawyerPin
        };

        // 2. SESSION object
        const session = {
            lastLogin: bootstrapData.user.lastLogin || 'Never',
            isFirstLogin: bootstrapData.user.lastLogin === 'First login'
        };

        // 3. WORKFLOW steps (SERVER builds array based on progress)
        const workflow = {
            steps: [
                {
                    label: 'Initial Contact',
                    status: 'completed',
                    statusLabel: 'Completed'
                },
                {
                    label: 'Consent Form',
                    status: bootstrapData.progress.consentSigned ? 'completed' : 'active',
                    statusLabel: bootstrapData.progress.consentSigned ? 'Completed' : 'In Progress'
                },
                {
                    label: 'INA Appointment',
                    status: bootstrapData.progress.consentSigned ? 'active' : 'pending',
                    statusLabel: bootstrapData.progress.consentSigned ? 'Ready' : 'Pending'
                },
                {
                    label: 'Assessment',
                    status: 'pending',
                    statusLabel: 'Pending'
                },
                {
                    label: 'Final Report',
                    status: 'pending',
                    statusLabel: 'Pending'
                }
            ]
        };

        // 4. CARDS (SERVER determines enabled/disabled states)
        const cards = {
            consentForm: {
                signed: bootstrapData.progress.consentSigned || false,
                status: bootstrapData.progress.consentSigned ? 'completed' : 'active',
                statusLabel: bootstrapData.progress.consentSigned ? 'Signed' : 'Action Required'
            },
            inaAppointment: {
                scheduled: false, // TODO: Add appointment tracking
                canSchedule: bootstrapData.progress.consentSigned || false,
                status: bootstrapData.progress.consentSigned ? 'active' : 'pending',
                statusLabel: bootstrapData.progress.consentSigned ? 'Ready to Schedule' : 'Awaiting Consent'
            },
            documentAccess: {
                enabled: bootstrapData.features.viewDocuments || false,
                status: bootstrapData.features.viewDocuments ? 'active' : 'pending',
                statusLabel: bootstrapData.features.viewDocuments ? 'Available' : 'Locked'
            },
            finalReport: {
                available: false, // TODO: Add report tracking
                status: 'pending',
                statusLabel: 'Pending Assessment'
            }
        };

        // 5. PROGRESS PERCENTAGE (SERVER calculates)
        let completedSteps = 0;
        const totalSteps = workflow.steps.length;
        workflow.steps.forEach(step => {
            if (step.status === 'completed') completedSteps++;
        });
        const progressPercentage = Math.round((completedSteps / totalSteps) * 100);

        // 6. CSRF TOKEN (SERVER generates)
        const csrfToken = server.jwt.sign({
            csrf: true,
            clientPin: clientPin,
            timestamp: Date.now()
        });

        // 7. NOTIFICATIONS (from SSOT bootstrap)
        const notifications = bootstrapData.notifications || {
            unreadCount: 0,
            items: []
        };

        // ==========================================
        // RENDER TEMPLATE WITH SERVER-COMPUTED DATA
        // ==========================================
        return reply.view('clientsDashboard.ejs', {
            title: 'QOLAE Clients Dashboard',
            client,
            session,
            workflow,
            cards,
            progressPercentage,
            csrfToken,
            notifications,
            progress: bootstrapData.progress,
            features: bootstrapData.features,
            caseInfo: bootstrapData.caseInfo,
            ssotBaseUrl: SSOT_BASE_URL,
            bootstrapData: JSON.stringify(bootstrapData)
        });

    } catch (error) {
        console.error('❌ Error loading dashboard:', error);
        return reply.code(500).send({ error: 'Failed to load dashboard' });
    }
});

// ==============================================
// LOCATION BLOCK H: ROUTES REGISTRATION
// ==============================================

// Client Workflow Routes (SSOT compliant - calls API for data)
await server.register(import('./routes/clientWorkflowRoutes.js'));

// ==============================================
// LOCATION BLOCK I: ROOT ROUTE
// ==============================================
server.get('/', async (request, reply) => {
    // Check if authenticated
    try {
        await request.jwtVerify();
        return reply.redirect('/clientsDashboard');
    } catch (error) {
        // Not authenticated, redirect to LoginPortal
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(loginUrl);
    }
});

// ==============================================
// LOCATION BLOCK J: HEALTH CHECK
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
// LOCATION BLOCK K: ERROR HANDLING
// ==============================================
server.setErrorHandler((error, request, reply) => {
    server.log.error(error);

    // Check if it's an auth error
    if (error.statusCode === 401) {
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(`${loginUrl}?error=Please login to continue.`);
    }

    reply.status(error.statusCode || 500).send({
        success: false,
        error: error.message || 'Internal Server Error',
        timestamp: new Date().toISOString(),
    });
});

// ==============================================
// LOCATION BLOCK L: SERVER START
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
        console.log('  🏠 Dashboard:     /clientsDashboard');
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