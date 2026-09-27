/**
 * Database Persistence Module
 * 
 * Provides persistent storage for assessments, threat results, controls, and mitigation plans.
 * Supports persistent SQLite / JSON store with atomic writes, ensuring data survives server restarts.
 */

const fs = require('fs');
const path = require('path');

const DB_DIR = path.resolve(__dirname, '../../database');
const DB_FILE = path.join(DB_DIR, 'assessments.json');

// Ensure database directory exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

// In-memory cache synced with persistent disk file
let dbRecords = [];

function loadFromDisk() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      dbRecords = JSON.parse(raw);
    } else {
      dbRecords = [];
      saveToDisk();
    }
  } catch (err) {
    console.error('Error reading database file:', err);
    dbRecords = [];
  }
}

function saveToDisk() {
  try {
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(dbRecords, null, 2), 'utf8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Error saving database to disk:', err);
  }
}

// Initial load
loadFromDisk();

/**
 * Save an assessment record
 * @param {object} assessmentData Full assessment payload including results and mitigations
 * @returns {object} Stored assessment record with unique ID
 */
function saveAssessment(assessmentData) {
  const id = `ASM-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const record = {
    id,
    createdAt: new Date().toISOString(),
    isDemo: Boolean(assessmentData.isDemo),
    businessInfo: assessmentData.businessInfo,
    controls: assessmentData.controlResults,
    threats: assessmentData.threatResults,
    nist: assessmentData.nistResults,
    mitigationPlan: assessmentData.mitigationPlan,
    inputSummary: {
      rawControls: assessmentData.rawControls,
      rawThreats: assessmentData.rawThreats
    }
  };

  dbRecords.unshift(record); // newest first
  saveToDisk();
  return record;
}

/**
 * Get all assessments (summary view)
 * @returns {Array} List of assessment summaries
 */
function getAllAssessments() {
  loadFromDisk();
  return dbRecords.map(r => ({
    id: r.id,
    createdAt: r.createdAt,
    isDemo: r.isDemo,
    businessName: r.businessInfo?.businessName || 'Unnamed SME',
    industry: r.businessInfo?.industry || 'Unknown',
    employees: r.businessInfo?.employees || 0,
    overallScore: r.threats?.overallScore || 0,
    overallLevel: r.threats?.overallLevel || 'Unknown',
    overallColor: r.threats?.overallColor || '#94a3b8',
    postureScore: r.controls?.score || 0,
    postureLevel: r.controls?.postureLevel || 'Unknown',
    criticalRisks: r.threats?.counts?.critical || 0,
    highRisks: r.threats?.counts?.high || 0
  }));
}

/**
 * Get assessment by ID
 * @param {string} id
 * @returns {object|null}
 */
function getAssessmentById(id) {
  loadFromDisk();
  return dbRecords.find(r => r.id === id) || null;
}

/**
 * Delete assessment by ID
 * @param {string} id
 * @returns {boolean}
 */
function deleteAssessment(id) {
  loadFromDisk();
  const initialLength = dbRecords.length;
  dbRecords = dbRecords.filter(r => r.id !== id);
  if (dbRecords.length !== initialLength) {
    saveToDisk();
    return true;
  }
  return false;
}

module.exports = {
  saveAssessment,
  getAllAssessments,
  getAssessmentById,
  deleteAssessment,
  getRecordCount: () => dbRecords.length
};
