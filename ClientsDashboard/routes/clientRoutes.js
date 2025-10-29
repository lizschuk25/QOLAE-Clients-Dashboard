// ==============================================
// CLIENTS DASHBOARD - CLIENT ROUTES
// ==============================================
// Purpose: Consent signing, appointments, documents, and report access
// Author: Liz
// Date: October 28, 2025
// Database: qolae_hrcompliance (clients table)
// ==============================================

import pg from 'pg';

const { Pool } = pg;

// Database connection (HR Compliance database)
const hrcDb = new Pool({
  connectionString: process.env.HRCOMPLIANCE_DATABASE_URL
});

// ==============================================
// AUTHENTICATION MIDDLEWARE
// ==============================================
async function authenticateClient(request, reply) {
  try {
    await request.jwtVerify();

    // Verify client role
    if (request.user.role !== 'client') {
      throw new Error('Unauthorized');
    }
  } catch (error) {
    reply.code(401).send({
      success: false,
      error: 'Authentication required'
    });
  }
}

export default async function clientRoutes(fastify, options) {

  // ==============================================
  // CLIENTS DASHBOARD - MAIN VIEW
  // ==============================================
  fastify.get('/clients-dashboard', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    const { pin, name } = request.user;

    try {
      // Get client data
      const clientResult = await hrcDb.query(
        `SELECT client_pin, client_name, email, phone,
                consent_signed, consent_signed_at,
                ina_appointment_scheduled, ina_appointment_date,
                document_access_enabled, final_report_available,
                workflow_status, created_at
         FROM clients
         WHERE client_pin = $1`,
        [pin]
      );

      if (clientResult.rows.length === 0) {
        return reply.code(404).send({ success: false, error: 'Client not found' });
      }

      const client = clientResult.rows[0];

      // Get notifications (last 10)
      const notificationsResult = await hrcDb.query(
        `SELECT id, title, message, read, created_at
         FROM client_notifications
         WHERE client_pin = $1
         ORDER BY created_at DESC
         LIMIT 10`,
        [pin]
      );

      const notifications = notificationsResult.rows;
      const unreadCount = notifications.filter(n => !n.read).length;

      // Calculate workflow progress
      const workflowSteps = [
        {
          label: 'Initial Contact',
          status: 'completed', // Always completed if they're logged in
          statusLabel: 'Completed'
        },
        {
          label: 'Consent Form',
          status: client.consent_signed ? 'completed' : 'active',
          statusLabel: client.consent_signed ? 'Completed' : 'Action Required'
        },
        {
          label: 'INA Appointment',
          status: client.ina_appointment_scheduled ? 'completed' : (client.consent_signed ? 'pending' : 'pending'),
          statusLabel: client.ina_appointment_scheduled ? 'Scheduled' : 'Ready to Schedule'
        },
        {
          label: 'Document Access',
          status: client.document_access_enabled ? 'active' : 'pending',
          statusLabel: client.document_access_enabled ? 'Now Available' : 'Requires Consent'
        },
        {
          label: 'Final Report',
          status: client.final_report_available ? 'completed' : 'pending',
          statusLabel: client.final_report_available ? 'Pending Assessment' : 'Pending Assessment'
        }
      ];

      // Calculate progress percentage
      const completedSteps = workflowSteps.filter(s => s.status === 'completed').length;
      const progressPercentage = Math.round((completedSteps / workflowSteps.length) * 100);

      // Card states
      const cards = {
        consentForm: {
          signed: client.consent_signed,
          status: client.consent_signed ? 'completed' : 'pending',
          statusLabel: client.consent_signed ? 'Completed' : 'Action Required'
        },
        inaAppointment: {
          scheduled: client.ina_appointment_scheduled,
          canSchedule: client.consent_signed,
          status: client.ina_appointment_scheduled ? 'completed' : (client.consent_signed ? 'active' : 'pending'),
          statusLabel: client.ina_appointment_scheduled ? 'Ready to Schedule' : 'Pending Consent'
        },
        documentAccess: {
          enabled: client.document_access_enabled,
          status: client.document_access_enabled ? 'active' : 'pending',
          statusLabel: client.document_access_enabled ? 'Now Available' : 'Requires Consent'
        },
        finalReport: {
          available: client.final_report_available,
          status: client.final_report_available ? 'completed' : 'pending',
          statusLabel: client.final_report_available ? 'Pending Assessment' : 'Pending Assessment'
        }
      };

      // Session data
      const session = {
        lastLogin: new Date().toLocaleString('en-GB'),
        isFirstLogin: !client.last_login
      };

      // CSRF token
      const csrfToken = fastify.jwt.sign({ csrf: true, pin });

      return reply.view('clients-dashboard.ejs', {
        client: {
          id: client.client_pin,
          name: client.client_name,
          firstName: client.client_name.split(' ')[0],
          email: client.email
        },
        workflow: {
          steps: workflowSteps,
          currentStepLabel: client.workflow_status || 'in progress'
        },
        progressPercentage,
        cards,
        notifications: {
          items: notifications.map(n => ({
            id: n.id,
            title: n.title,
            message: n.message,
            read: n.read,
            timeAgo: getTimeAgo(n.created_at)
          })),
          unreadCount
        },
        session,
        csrfToken
      });

    } catch (error) {
      fastify.log.error('Error loading clients dashboard:', error);
      return reply.code(500).send({ success: false, error: 'Failed to load dashboard' });
    }
  });

  // ==============================================
  // SIGN CONSENT FORM (DIGITAL SIGNATURE)
  // ==============================================
  fastify.post('/api/consent/sign', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    const { pin } = request.user;

    try {
      // Get signature from multipart form
      const data = await request.file();
      
      if (!data) {
        return reply.code(400).send({
          success: false,
          error: 'Signature file is required'
        });
      }

      const signatureBuffer = await data.toBuffer();
      
      // Save signature and update client
      await hrcDb.query(
        `UPDATE clients
         SET consent_signed = TRUE,
             consent_signed_at = NOW(),
             consent_signature_data = $1,
             document_access_enabled = TRUE,
             workflow_status = 'consent_completed'
         WHERE client_pin = $2`,
        [signatureBuffer, pin]
      );

      // Log activity
      await hrcDb.query(
        `INSERT INTO client_activity_log (client_pin, activity_type, activity_description, created_at)
         VALUES ($1, $2, $3, NOW())`,
        [pin, 'consent_signed', 'Client signed consent form digitally']
      );

      // TODO: Trigger blockchain hash generation for consent form
      // TODO: Send notification to Case Manager

      return reply.send({
        success: true,
        message: 'Consent form signed successfully'
      });

    } catch (error) {
      fastify.log.error('Error signing consent:', error);
      return reply.code(500).send({
        success: false,
        error: 'Failed to sign consent form'
      });
    }
  });

  // ==============================================
  // MARK NOTIFICATION AS READ
  // ==============================================
  fastify.post('/api/notifications/:id/read', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    const { id } = request.params;
    const { pin } = request.user;

    try {
      await hrcDb.query(
        `UPDATE client_notifications
         SET read = TRUE, read_at = NOW()
         WHERE id = $1 AND client_pin = $2`,
        [id, pin]
      );

      return reply.send({ success: true });

    } catch (error) {
      fastify.log.error('Error marking notification as read:', error);
      return reply.code(500).send({
        success: false,
        error: 'Failed to mark notification as read'
      });
    }
  });

  // ==============================================
  // CONSENT DOWNLOAD (VIEW SIGNED FORM)
  // ==============================================
  fastify.get('./consent/download', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    // TODO: Fetch signed consent form PDF from blockchain/storage
    return reply.send({ success: false, error: 'Not implemented yet' });
  });

  // ==============================================
  // DOCUMENT ACCESS
  // ==============================================
  fastify.get('./documents', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    // TODO: Fetch client documents from secure storage
    return reply.send({ success: false, error: 'Not implemented yet' });
  });

  // ==============================================
  // FINAL REPORT VIEW
  // ==============================================
  fastify.get('./report/view', {
    preHandler: authenticateClient
  }, async (request, reply) => {
    // TODO: Fetch final INA report from secure storage
    return reply.send({ success: false, error: 'Not implemented yet' });
  });
}

// ==============================================
// HELPER FUNCTIONS
// ==============================================

function getTimeAgo(date) {
  const seconds = Math.floor((new Date() - new Date(date)) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;
  
  return new Date(date).toLocaleDateString('en-GB');
}

