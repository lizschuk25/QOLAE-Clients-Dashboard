# QOLAE Portal - Client Dashboard

🚀 **Blockchain-secured legal document management system** built with Fastify and EJS.

## 📋 Overview

The QOLAE Portal is a secure, GDPR-compliant platform for managing Immediate Needs Assessments (INA) workflows. All critical documents are secured on blockchain infrastructure for immutability and audit trail purposes.

### Key Features

- ✅ **Blockchain Security**: All documents stored with immutable hash verification
- ✅ **Digital Signatures**: Canvas-based signature capture with blockchain timestamps
- ✅ **GDPR Compliant**: Full data protection and privacy controls
- ✅ **Calendar Integration**: Automatic sync with Case Manager calendars
- ✅ **Real-time Notifications**: Keep clients informed at every step
- ✅ **Workflow Management**: 5-step process from initial contact to final report
- ✅ **Multi-factor Authentication**: Secure PIN-based access
- ✅ **Responsive Design**: Works on desktop, tablet, and mobile

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      QOLAE Portal                           │
├─────────────────────────────────────────────────────────────┤
│  Frontend (EJS Templates)                                   │
│  ├─ client-dashboard.ejs                                    │
│  ├─ appointment-scheduler.ejs                               │
│  └─ document-vault.ejs                                      │
├─────────────────────────────────────────────────────────────┤
│  Backend (Fastify)                                          │
│  ├─ Routes                                                  │
│  │   ├─ /client/dashboard                                   │
│  │   ├─ /client/api/consent/sign                           │
│  │   └─ /client/api/appointment/book                       │
│  ├─ Middleware                                              │
│  │   ├─ Authentication                                      │
│  │   ├─ CSRF Protection                                     │
│  │   └─ Rate Limiting                                       │
│  └─ Services                                                │
│      ├─ Blockchain Integration                              │
│      ├─ Email Notifications                                 │
│      └─ Calendar Sync                                       │
├─────────────────────────────────────────────────────────────┤
│  Data Layer                                                 │
│  ├─ Database (PostgreSQL/MongoDB/MySQL)                    │
│  └─ Blockchain Network                                      │
└─────────────────────────────────────────────────────────────┘
```

## 🚦 Workflow Steps

1. **Initial Contact** - Client receives PIN/ID via email
2. **Consent Form** - Digital signature capture with blockchain recording
3. **INA Appointment** - Schedule assessment (syncs with Case Manager)
4. **Document Access** - Secure vault with verified documents
5. **Final Report** - INA results with integrity verification

## 📦 Installation

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0
- Database (PostgreSQL, MongoDB, or MySQL)
- Blockchain network access

### Setup Steps

1. **Clone the repository**
2. **Install dependencies**
3. **Configure environment variables**
4. **Set up database**
5. **Generate secrets**
```bash
# Generate strong random strings for SESSION_SECRET and COOKIE_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
6. **Start the server**
# Production

The server will start at `http://localhost:3010` (clients.qolae.com) and websocket:3011(SSOT access)

## 🔧 Configuration

### Environment Variables

See `.env.example` for all available configuration options.

**Critical variables to configure:**
- `SESSION_SECRET` - Session encryption key
- `COOKIE_SECRET` - Cookie signing key
- `DATABASE_URL` - Database connection string
- `BLOCKCHAIN_API_KEY` - Blockchain network credentials
- `SENDGRID_API_KEY` - Email service credentials
- `GOOGLE_CALENDAR_CREDENTIALS` - Calendar sync credentials

### Blockchain Integration

The system supports blockchain compliance that may implement the following:

- **Ethereum/EVM-compatible chains**
- **Hyperledger Fabric**
- **Custom blockchain networks**

Configure your blockchain provider in the `.env` file and implement the blockchain service decorators in `app.js`:

```javascript
fastify.decorate('blockchain', {
  storeDocument: async (data) => {
    // Your blockchain integration
  },
  verifyDocumentHash: async (hash, txId) => {
    // Hash verification logic
  }
});
```

## 🔐 Security

### Authentication

Clients access the portal via:
1. **Email invitation** with unique PIN ID
2. **2-factor authentication** (can be enabled)
3. **Session management** with secure cookies

### Data Protection

- All data encrypted in transit (HTTPS)
- Passwords hashed with bcrypt
- CSRF protection on all forms
- Rate limiting to prevent abuse
- Helmet security headers
- Input validation and sanitization

### Blockchain Security

- Document hashes stored immutably
- Tamper detection on all retrievals
- Audit trail for all actions
- Time-stamped signatures

## 📁 Project Structure

```
qolae-portal/
├── app.js                          # Main application entry point
├── package.json                    # Dependencies and scripts
├── .env.example                    # Environment variables template
├── routes/
│   ├── client-dashboard.js         # Client dashboard routes
│   ├── auth.js                     # Authentication routes
│   └── case-manager-dashboard.js   # Case Manager routes (future)
├── views/
│   ├── client-dashboard.ejs        # Main client dashboard
│   ├── appointment-scheduler.ejs   # Appointment booking
│   ├── document-vault.ejs          # Document access
│   └── error.ejs                   # Error pages
├── models/
│   ├── clients.js                  # Client data model
│   ├── consentForms.js             # Consent form model
│   ├── appointments.js             # Appointment model
│   └── notifications.js            # Notification model
├── public/
│   ├── css/                        # Stylesheets
│   ├── js/                         # Client-side JavaScript
│   └── images/                     # Images and assets
└── config/
    ├── database.js                 # Database configuration
    └── blockchain.js               # Blockchain configuration
```

## 🚀 Deployment
Customised Live Server on Hertzner

## 🔗 API Endpoints

### Client Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/client/dashboard` | Main dashboard view |
| POST | `/client/api/consent/sign` | Submit digital signature |
| GET | `/client/consent/download` | Download consent PDF |
| POST | `/client/api/notifications/:id/read` | Mark notification as read |
| GET | `/client/appointment/schedule` | Appointment scheduler page |
| POST | `/client/api/appointment/book` | Book appointment |
| GET | `/client/documents` | Document vault |
| GET | `/client/report/view` | View final report |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/login` | Login page |
| POST | `/api/auth/login` | Process login |
| POST | `/api/auth/logout` | Logout |

## 🧪 Testing


## 📊 Monitoring

### Logging

Logs are output via Fastify's built-in logger (Pino):

### Health Checks

```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-28T10:30:00.000Z",
  "blockchain": "connected"
}
```

## 🛠️ Troubleshooting

### Common Issues

**"Cannot connect to database"**
- Check `DATABASE_URL` in `.env`
- Ensure database server is running
- Verify credentials and permissions

**"Blockchain transaction failed"**
- Verify blockchain API credentials
- Check network connectivity
- Ensure sufficient balance for gas fees

**"Email not sending"**
- Verify email service credentials
- Check spam folder
- Verify FROM email is verified with provider

**"Calendar sync not working"**
- Check calendar API credentials
- Verify OAuth scopes/permissions
- Test calendar API connection separately

## 📄 License

PROPRIETARY - All rights reserved by QOLAE

## 👥 Support

For support and questions:
- **Email**: admin@qolae.com
- **Documentation**: [admin@qolae.com](https://hrcompliance.qolae.com)

## 🎯 Roadmap

- [ ] CaseManagers Dashboard
- [ ] Lawyers Dashboard
- [ ] Multi-language support
- [ ] Advanced analytics
- [ ] Webhooks for integrations
- [ ] API for third-party access
- [ ] Two-factor authentication
- [ ] Document e-signature (DocuSign integration)

## 🙏 Credits

Built with ❤️ by Liz for QOLAE

**Technologies:**
- [Fastify](https://www.fastify.io/) - Web framework
- [EJS](https://ejs.co/) - Templating engine
- [Node.js](https://nodejs.org/) - Runtime
- Blockchain networks - Document security

---

**Last Updated**: 25th November 2025

### **📋 STEP 1D: CLIENTS WORKFLOW**✅
**Status**: Lower priority, simpler workflow

#### **1D.1 - Client Registration** ⏳ ✅
- [ ] **Basic info collection**
- [ ] **Generate client PIN**

#### **1D.2 - Client Consent Form** ⏳ ✅
- [ ] **Digital signature**
- [ ] **Consent tracking**

#### **1D.3 - Client Portal Access** ⏳ ✅
- [ ] **View case status**
- [ ] **View documents**
- [ ] **Minimal access (read-only)**

---