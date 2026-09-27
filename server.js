/**
 * Express Backend Server
 * Cybersecurity Risk Assessment Framework for Small Businesses
 */

const express = require('express');
const path = require('path');
const fs = require('fs');

const { THREAT_DEFINITIONS } = require('./data/threatDefinitions');
const { CONTROL_DEFINITIONS } = require('./data/controlDefinitions');
const { DEMO_ASSESSMENT_INPUT } = require('./data/demoData');
const { calculateAssessment } = require('./services/riskEngine');
const { generateMitigationPlan } = require('./services/mitigationEngine');
const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 5000;

// Security & Utility Middleware
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Serve frontend static assets
const FRONTEND_DIR = path.resolve(__dirname, '../frontend');
app.use(express.static(FRONTEND_DIR));

// Simple Input Sanitizer
function sanitizeString(str, maxLen = 255) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

// Input Validator
function validateAssessmentPayload(body) {
  const errors = [];
  const { businessInfo = {}, threats = {}, controls = {} } = body;

  const businessName = sanitizeString(businessInfo.businessName);
  if (!businessName || businessName.length < 2) {
    errors.push('Business Name is required (minimum 2 characters).');
  }

  const industry = sanitizeString(businessInfo.industry);
  if (!industry) {
    errors.push('Industry is required.');
  }

  const employees = parseInt(businessInfo.employees, 10);
  if (isNaN(employees) || employees < 1 || employees > 100000) {
    errors.push('Number of employees must be a valid positive integer.');
  }

  const devices = parseInt(businessInfo.devices, 10);
  if (isNaN(devices) || devices < 1 || devices > 100000) {
    errors.push('Number of devices must be a valid positive integer.');
  }

  // Validate threat inputs
  for (const def of THREAT_DEFINITIONS) {
    const t = threats[def.id] || {};
    const l = parseInt(t.likelihood, 10);
    const s = parseInt(t.severity, 10);
    const i = parseInt(t.impact, 10);

    if (isNaN(l) || l < 1 || l > 5) {
      errors.push(`Threat '${def.name}' Likelihood must be an integer between 1 and 5.`);
    }
    if (isNaN(s) || s < 1 || s > 5) {
      errors.push(`Threat '${def.name}' Severity must be an integer between 1 and 5.`);
    }
    if (isNaN(i) || i < 1 || i > 5) {
      errors.push(`Threat '${def.name}' Business Impact must be an integer between 1 and 5.`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: {
      businessInfo: {
        businessName,
        industry,
        employees,
        devices,
        locations: Math.max(1, parseInt(businessInfo.locations, 10) || 1),
        usesCloud: Boolean(businessInfo.usesCloud),
        storesCustomerData: Boolean(businessInfo.storesCustomerData),
        hasRemoteEmployees: Boolean(businessInfo.hasRemoteEmployees)
      },
      controls,
      threats
    }
  };
}

// ==========================================
// REST API ROUTES
// ==========================================

// 1. Health check & Metadata
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    framework: 'Cybersecurity Risk Assessment Framework for Small Businesses',
    version: '1.0.0',
    nistVersion: 'NIST CSF 2.0 Aligned',
    timestamp: new Date().toISOString(),
    recordCount: db.getRecordCount()
  });
});

// 2. Threat Catalog
app.get('/api/threats', (req, res) => {
  res.json({
    success: true,
    count: THREAT_DEFINITIONS.length,
    threats: THREAT_DEFINITIONS
  });
});

// 3. Security Controls Catalog
app.get('/api/controls', (req, res) => {
  res.json({
    success: true,
    count: CONTROL_DEFINITIONS.length,
    controls: CONTROL_DEFINITIONS
  });
});

// 4. Calculate Risk Assessment (without saving)
app.post('/api/assessments/calculate', (req, res) => {
  const validation = validateAssessmentPayload(req.body);
  if (!validation.isValid) {
    return res.status(400).json({ success: false, errors: validation.errors });
  }

  const calculation = calculateAssessment(validation.sanitized);
  const mitigationPlan = generateMitigationPlan(calculation);

  res.json({
    success: true,
    assessment: {
      ...calculation,
      mitigationPlan
    }
  });
});

// 5. Submit & Persist Assessment
app.post('/api/assessments', (req, res) => {
  const validation = validateAssessmentPayload(req.body);
  if (!validation.isValid) {
    return res.status(400).json({ success: false, errors: validation.errors });
  }

  const calculation = calculateAssessment(validation.sanitized);
  const mitigationPlan = generateMitigationPlan(calculation);

  const fullAssessment = {
    ...calculation,
    mitigationPlan,
    isDemo: Boolean(req.body.isDemo),
    rawControls: validation.sanitized.controls,
    rawThreats: validation.sanitized.threats
  };

  const savedRecord = db.saveAssessment(fullAssessment);

  res.status(201).json({
    success: true,
    message: 'Assessment calculated and saved successfully.',
    assessment: savedRecord
  });
});

// 6. Get Historical Assessments List
app.get('/api/assessments', (req, res) => {
  const list = db.getAllAssessments();
  res.json({
    success: true,
    count: list.length,
    assessments: list
  });
});

// 7. Get Single Assessment by ID
app.get('/api/assessments/:id', (req, res) => {
  const record = db.getAssessmentById(req.params.id);
  if (!record) {
    return res.status(404).json({ success: false, error: 'Assessment not found' });
  }
  res.json({
    success: true,
    assessment: record
  });
});

// 8. Delete Assessment by ID
app.delete('/api/assessments/:id', (req, res) => {
  const deleted = db.deleteAssessment(req.params.id);
  if (!deleted) {
    return res.status(404).json({ success: false, error: 'Assessment not found or already deleted' });
  }
  res.json({
    success: true,
    message: 'Assessment deleted successfully'
  });
});

// 9. Load Demo Assessment
app.get('/api/demo/load', (req, res) => {
  const calculation = calculateAssessment(DEMO_ASSESSMENT_INPUT);
  const mitigationPlan = generateMitigationPlan(calculation);

  const demoRecord = {
    ...calculation,
    mitigationPlan,
    isDemo: true,
    rawControls: DEMO_ASSESSMENT_INPUT.controls,
    rawThreats: DEMO_ASSESSMENT_INPUT.threats
  };

  const savedRecord = db.saveAssessment(demoRecord);

  res.json({
    success: true,
    isDemo: true,
    message: 'Demo assessment for TechNova Solutions loaded successfully.',
    assessment: savedRecord
  });
});

// 10. Export Assessment as CSV (Risk Register)
app.get('/api/export/:id/csv', (req, res) => {
  const record = db.getAssessmentById(req.params.id);
  if (!record) {
    return res.status(404).json({ success: false, error: 'Assessment not found' });
  }

  const threats = record.threats?.threats || [];
  let csv = 'Threat ID,Threat Name,NIST Function,Likelihood (1-5),Severity (1-5),Business Impact (1-5),Risk Score (0-125),Risk Level,Priority\n';

  for (const t of threats) {
    csv += `"${t.id}","${t.name}","${t.nistCategory}",${t.likelihood},${t.severity},${t.impact},${t.score},"${t.riskLevel}",${t.priority}\n`;
  }

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="risk_register_${record.id}.csv"`);
  res.send(csv);
});

// 11. Export Assessment as JSON
app.get('/api/export/:id/json', (req, res) => {
  const record = db.getAssessmentById(req.params.id);
  if (!record) {
    return res.status(404).json({ success: false, error: 'Assessment not found' });
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="assessment_${record.id}.json"`);
  res.send(JSON.stringify(record, null, 2));
});

// Catch-all route to serve the frontend SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

// Start Server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(` CYBERSECURITY RISK ASSESSMENT FRAMEWORK FOR SMEs`);
    console.log(` Server running on http://localhost:${PORT}`);
    console.log(` API Health: http://localhost:${PORT}/api/health`);
    console.log(`====================================================`);
  });
}

module.exports = app;
