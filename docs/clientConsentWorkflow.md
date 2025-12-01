# 📋 CLIENT CONSENT WORKFLOW IMPLEMENTATION

**Date:** October 28, 2025  
**Author:** Liz 👑  
**Architecture:** Simplified Centralized PIN ID Generation 
---

## 🎯 WORKFLOW OVERVIEW

```
┌──────────────────────────────────────────────────────────────┐
│ STEP 1: LAWYER CREATES CONSENT FORM                          │
│ (Lawyers Dashboard - consentModal.ejs)                       │
│ - Lawyer enters client details (name, email, DOB, address)   │
│ - Click "Continue to Form Preview" /record registered into database qolae_lawyers)                          │
└─────────────────┬────────────────────────────────────────────┘
                  ↓ (API Call)
┌──────────────────────────────────────────────────────────────┐
│ STEP 1A: CLIENT PIN GENERATION                               │
|(Lawyers |Dashboard Database sql schema in qolae_lawyers)     │
  GenerateClientPIN: Law Firm first 2-3 letters and then First |
  letter of first name Surname of client followed by 6 digit   | number:CL-WD-123456                                          |    
  Send consent email with PIN link ✉️                          │
└─────────────────┬────────────────────────────────────────────┘
                  ↓ (Email with PIN link)
┌──────────────────────────────────────────────────────────────┐
│ STEP 2: CLIENT RECEIVES EMAIL                                │
│ Subject: "QOLAE Consent Form - Action Required"              │
│ Body: "Click here to access your secure portal"              │
│ Link: https://clients.qolae.com/login?pin=CLT-WX-123456      │
└─────────────────┬────────────────────────────────────────────┘
                  ↓ (Client clicks link)
┌──────────────────────────────────────────────────────────────┐
│ STEP 3: CLIENT LOGS IN & SIGNS CONSENT                       │
│ (Clients Dashboard - clients.qolae.com)                      │
│ - 2FA: PIN + Email verification                              │
│ - View consent form                                          │
│ - Digital signature                                          │
│ - Submit consent                                             │
└─────────────────┬────────────────────────────────────────────┘
                  ↓ (Status update)
┌──────────────────────────────────────────────────────────────┐
│ STEP 4: LIZ REVIEWS & SCHEDULES INA VISIT                    │
│ (CaseManagers Dashboard)                                     │
│ - View signed consent                                        │
│ - Schedule INA appointment                                   │
│ - Trigger Case Manager workspace population                  │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 FILE STRUCTURE

### **Lawyers Dashboard** (`QOLAE-Lawyers-Dashboard`)
```
LawyersDashboard/
├── views/
│   └── consentModal.ejs                   ✅ UPDATED (ServerSide to call API)
├── routes/
│   └── consentRoutes.js                   ✅ NEW (API routes for consent workflow)
└── server.js                              ✅ UPDATED (Register consent routes)
```

### ** Lawyers Dashboard** (`QOLAE-Lawyers-Dashboard`) linking to Clients Dashboard and bringing in the existing SSOT aspects in perhaps 
```
├── routes/
│   └── clientsRoutes.js                   ✅ NEW (Client registration API)
├── utils/
│   └── clientIdGenerator.js               ✅ NEW (Centralized PIN generator)
├── database/
│   └── add_client_id_generation_tables.sql ✅ NEW (Database migration)
└── hrc_server.js (change this over to cd_server.js/server.js or fastify_server                       ✅ UPDATED (Register   clients routes)
```

---

## 🗄️ DATABASE SCHEMA

### **1. `client_id_sequences` Table**
Generates sequential form reference numbers.

```sql
CREATE TABLE client_id_sequences (
  sequence_number SERIAL PRIMARY KEY,
  law_firm_code VARCHAR(10) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**Example Records:**
| sequence_number | law_firm_code | created_at           |
|-----------------|---------------|---------------------|
| 1               | WX            | 2025-10-28 10:00:00 |
| 2               | WX            | 2025-10-28 10:05:00 |
| 3               | ABC           | 2025-10-28 10:10:00 |

**Generated IDs:**
- CF-WX-000001
- CF-WX-000002
- CF-ABC-000003

---

### **2. `clients` Table (Updated)**
Stores all client records with consent workflow status.

```sql
ALTER TABLE clients 
ADD COLUMN form_reference VARCHAR(50) UNIQUE,        -- CF-WX-002690
ADD COLUMN client_pin VARCHAR(50) UNIQUE,            -- CLT-WX-123456
ADD COLUMN status VARCHAR(50) DEFAULT 'pending_consent',
ADD COLUMN created_by VARCHAR(50) DEFAULT 'lawyer',
ADD COLUMN law_firm_code VARCHAR(10),                -- WX, ABC, etc.
ADD COLUMN assigned_lawyer_pin VARCHAR(50),          -- LWR-WX-001
ADD COLUMN consent_sent_at TIMESTAMP,
ADD COLUMN consent_signed_at TIMESTAMP,
ADD COLUMN consent_signature_data TEXT,
ADD COLUMN ina_appointment_scheduled BOOLEAN DEFAULT FALSE,
ADD COLUMN ina_appointment_date TIMESTAMP;
```

**Status Flow:**
```
pending_consent → consent_sent → consent_signed → active
```

---

## 🔐 ID GENERATION LOGIC

### **Client PIN Format:** `CLT-{LAWFIRM}-{RANDOM6}`
- Example: `CLT-WX-123456`
- Purpose: Client portal login
- Generation: 6-digit random number

### **Form Reference Format:** `CF-{LAWFIRM}-{SEQUENCE6}`
- Example: `CF-WX-002690`
- Purpose: Tracking & email subject line
- Generation: Auto-incrementing sequence number

### **Law Firm Code Extraction:**
From Lawyer PIN: `LWR-WX-001` → `WX`

---

## 🔌 API ENDPOINTS

### **Lawyers Dashboard** (Port 3002)

#### **1. Create Client Consent**
```http
POST /api/consent/create
Content-Type: application/json

{
  "clientName": "Sarah Johnson",
  "clientEmail": "sarah@example.com",
  "clientDOB": "1985-03-15",
  "clientAddress": "42 Oak Lane, Manchester, M1 5XY",
  "clientPhone": "07890 123456",
  "lawyerPin": "LWR-WX-001"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Consent form sent successfully to client",
  "data": {
    "clientPin": "CLT-WX-123456",
    "formReference": "CF-WX-002690",
    "clientName": "Sarah Johnson",
    "clientEmail": "sarah@example.com",
    "emailSent": true,
    "emailSentAt": "2025-10-28T10:30:00.000Z",
    "portalUrl": "https://clients.qolae.com/login?pin=CLT-WX-123456"
  }
}
```

#### **2. Get Consent Status**
```http
GET /api/consent/status/CF-WX-002690
```

#### **3. Resend Consent Email**
```http
POST /api/consent/resend
Content-Type: application/json

{
  "formReference": "CF-WX-002690"
}
```

#### **4. Get All Clients for Lawyer**
```http
GET /api/consent/clients/LWR-WX-001
```

---

### **HR Compliance Dashboard** (Port 3012)

#### **1. Register Client (Internal API)**
```http
POST /api/clients/register
Content-Type: application/json

{
  "clientName": "Sarah Johnson",
  "clientEmail": "sarah@example.com",
  "clientDOB": "1985-03-15",
  "clientAddress": "42 Oak Lane, Manchester, M1 5XY",
  "clientPhone": "07890 123456",
  "lawFirmCode": "WX",
  "assignedLawyerPin": "LWR-WX-001",
  "assignedLawyerName": "John Smith",
  "lawFirmName": "Woodthorpe-Wright & Partners",
  "sendInvitationEmail": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Client registered successfully",
  "clientPin": "CLT-WX-123456",
  "formReference": "CF-WX-002690",
  "clientName": "Sarah Johnson",
  "clientEmail": "sarah@example.com",
  "emailSent": true,
  "emailSentAt": "2025-10-28T10:30:00.000Z",
  "status": "consent_sent",
  "portalUrl": "https://clients.qolae.com/login?pin=CLT-WX-123456"
}
```

#### **2. Get Consent Status (Public API)**
```http
GET /api/clients/consent-status/CF-WX-002690
```

#### **3. Get Clients by Lawyer**
```http
GET /api/clients/by-lawyer/LWR-WX-001
```

#### **4. Resend Consent Email**
```http
POST /api/clients/resend-consent
Content-Type: application/json

{
  "formReference": "CF-WX-002690"
}
```

---

## 📧 EMAIL TEMPLATE (TO BE IMPLEMENTED)

### **Subject:** `QOLAE Consent Form - Action Required (Ref: CF-WX-002690)`

### **Body:**
```
Dear Sarah Johnson,

I hope this email letter finds you well.

As discussed with your legal team at [LawFirmName], we need your 
consent to proceed with assessing and addressing your rehabilitation and care needs.

🔐 Your Secure Portal Access:
   Client PIN: CLT-WX-123456
   https://clients.qolae.com/login?pin=ABC-DE-123456 //this link will be hidden behind the actual PIN number as a hyperlink and not exposed to human eyes

📋 What you need to do:
   1. Click the link above to access your secure portal

   2. Verify your email address this will take you to a 2FA page

   3. Click on Send email, check your email for the secure number

   4. Enter this number into the verification box, you will then be directed to a 
   secure login page to create a password. Keep this safe.

   5. You will then be directed to your own personal CLients Dashboard Workspace

   6. Review the consent form carefully

   7. Sign the form digitally

   8. Submit the completed form

   9. To return to Your Clients Dashboard at any time, 
   just click on the link in this email.

If you have any questions, please contact us.

I look forward to seeing you soon.

Liz 

Kindest Regards,
QOLAE Case Management Team
Quality of Life & Excellence


---

## ⚠️ TODO: IMPLEMENT EMAIL SENDING

### **Location:** `QOLAE-HRCompliance-Dashboard/utils/sendConsentEmail.js`

```javascript
export async function sendConsentEmail({
  clientName,
  clientEmail,
  clientPin,
  formReference,
  lawFirmName,
  lawyerName
}) {
  // TODO: Implement email sending using nodemailer or your email service
  // Use the email template above
  
  const emailBody = `
    Dear ${clientName},
    
    I hope this message finds you well.
    
    As discussed with your legal team at ${lawFirmName}, we need your 
    consent to proceed with assessing and addressing your rehabilitation and care needs.
    
    🔐 Your Secure Portal Access:
       Client PIN: ${clientPin}
       Portal Link: https://clients.qolae.com/login?pin=${clientPin}
       Form Reference: ${formReference}
    
    📋 What you need to do:
       1. Click the link above to access your secure portal
       2. Verify your email address
       3. Review the consent form carefully
       4. Sign the form digitally
       5. Submit the completed form
    
    If you have any questions, please don't hesitate to contact us.
    
    Thank you for your cooperation.
    
    Best regards,
    QOLAE Case Management Team
    Quality of Life & Excellence
  `;
  
  // Send email here...
  
  return {
    success: true,
    emailSent: true,
    sentAt: new Date().toISOString()
  };
}
```

---

## 🚀 DEPLOYMENT STEPS

### **1. Apply Database Migration**
```bash
ssh root@91.99.184.77
cd /var/www/hrcompliance.qolae.com/database
psql -U hrcompliance_user -d qolae_hrcompliance -f add_client_id_generation_tables.sql
```

### **2. Upload New Files to Lawyers Dashboard**
```bash
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-Lawyers-Dashboard/LawyersDashboard/routes/consentRoutes.js root@91.99.184.77:/var/www/lawyers.qolae.com/LawyersDashboard/routes/
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-Lawyers-Dashboard/LawyersDashboard/views/consentModal.ejs root@91.99.184.77:/var/www/lawyers.qolae.com/LawyersDashboard/views/
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-Lawyers-Dashboard/LawyersDashboard/server.js root@91.99.184.77:/var/www/lawyers.qolae.com/LawyersDashboard/
```

### **3. Upload New Files to HR Compliance Dashboard**
```bash
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-HRCompliance-Dashboard/routes/clientsRoutes.js root@91.99.184.77:/var/www/hrcompliance.qolae.com/routes/
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-HRCompliance-Dashboard/utils/clientIdGenerator.js root@91.99.184.77:/var/www/hrcompliance.qolae.com/utils/
scp /Users/lizchukwu_1/QOLAE-Online-Portal/QOLAE-HRCompliance-Dashboard/hrc_server.js root@91.99.184.77:/var/www/hrcompliance.qolae.com/
```

### **4. Restart PM2**
```bash
ssh root@91.99.184.77
pm2 flush && pm2 restart ecosystem.config.js --update-env
```

---

## ✅ TESTING CHECKLIST

- [ ] Lawyer can create consent form (Step 1)
- [ ] Client PIN & Form Reference generated correctly
- [ ] Client record inserted into database
- [ ] Email sent to client (TODO: implement email function)
- [ ] Lawyer sees success message with form reference
- [ ] Lawyer can view consent status
- [ ] Lawyer can resend consent email
- [ ] Client can log in with PIN (Clients Dashboard)
- [ ] Client can view and sign consent form
- [ ] HR Compliance can see all pending consents
- [ ] Liz can schedule INA after consent signed

---

## 📊 BENEFITS OF THIS ARCHITECTURE

1. **✅ No Manual PIN Generation:** Fully automated
2. **✅ Single Source of Truth:** HR Compliance owns all client data
3. **✅ Consistent ID Format:** CLT-XX-123456 & CF-XX-002690
4. **✅ No Duplicate Clients:** Unique constraints on PIN and Form Reference
5. **✅ Easy Tracking:** Form reference visible to both lawyer and client
6. **✅ Audit Trail:** Every action logged in `client_activity_log`
7. **✅ Scalable:** Works for multiple law firms (WX, ABC, etc.)
8. **✅ Simple Workflow:** Lawyer enters details → System does the rest

---

## 🎉 COMPLETED!

**Status:** ✅ READY FOR TESTING (pending email implementation)

**Next Steps:**
1. Implement `sendConsentEmail()` function
2. Test Lawyers Dashboard consent creation
3. Test Clients Dashboard login with PIN
4. Test consent signing workflow
5. Deploy to production

---

**Date:** October 28, 2025  
**Implementation Time:** ~2 hours  
**Simplified By:** ClaudeAI's Architecture Proposal 🚀

