/**
 * Application Controller & UI State Engine
 * Manages views, interactive assessment wizard, charts, risk matrix, risk register, and reports.
 */

// Global State
let currentAssessment = null;
let charts = {};
let riskRegisterData = [];
let sortDirection = { column: 'score', ascending: false };

// DOM Ready Init
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initFormControls();
  initThreatSliders();
  initModal();

  // Check URL hash for direct view navigation or default to landing
  const hash = window.location.hash.replace('#', '') || 'landing';
  switchView(hash);

  // Automatically load demo data if no assessment exists yet
  apiClient.loadDemoAssessment().then(demoData => {
    populateAssessmentData(demoData);
  }).catch(err => console.log('Demo preload notice:', err));
});

/**
 * View Navigation System
 */
function initNavigation() {
  document.querySelectorAll('[data-view-target]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = btn.getAttribute('data-view-target');
      switchView(target);
    });
  });

  // Header Quick Action Buttons
  const startBtn = document.getElementById('nav-start-assessment-btn');
  if (startBtn) {
    startBtn.addEventListener('click', () => switchView('wizard'));
  }

  const demoBtn = document.getElementById('nav-load-demo-btn');
  if (demoBtn) {
    demoBtn.addEventListener('click', loadDemoData);
  }

  const printBtn = document.getElementById('nav-print-report-btn');
  if (printBtn) {
    printBtn.addEventListener('click', () => {
      switchView('report');
      setTimeout(() => window.print(), 350);
    });
  }
}

function switchView(viewName) {
  // Hide all views
  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.remove('active');
  });

  // Remove active from nav links
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.remove('active');
    if (btn.getAttribute('data-view-target') === viewName) {
      btn.classList.add('active');
    }
  });

  // Show target view
  const targetSec = document.getElementById(`view-${viewName}`);
  if (targetSec) {
    targetSec.classList.add('active');
    window.location.hash = viewName;
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Refresh charts if entering dashboard
    if (viewName === 'dashboard' && currentAssessment) {
      renderCharts(currentAssessment);
    }
  }
}

/**
 * Assessment Wizard Form Controls
 */
let currentWizardStep = 1;

function initFormControls() {
  // Step indicator clicks
  document.querySelectorAll('.wizard-step-item').forEach(step => {
    step.addEventListener('click', () => {
      const targetStep = parseInt(step.getAttribute('data-step'), 10);
      goToWizardStep(targetStep);
    });
  });

  // Next/Prev Buttons
  document.querySelectorAll('[data-wizard-nav]').forEach(btn => {
    btn.addEventListener('click', () => {
      const dir = btn.getAttribute('data-wizard-nav');
      if (dir === 'next') {
        if (validateStep(currentWizardStep)) {
          goToWizardStep(currentWizardStep + 1);
        }
      } else if (dir === 'prev') {
        goToWizardStep(currentWizardStep - 1);
      }
    });
  });

  // Form Submission
  const form = document.getElementById('assessment-wizard-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!validateStep(1) || !validateStep(2) || !validateStep(3)) {
        alert('Please complete all required fields properly before submitting.');
        return;
      }

      const payload = extractFormData();
      const submitBtn = document.getElementById('submit-assessment-btn');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '⚡ Calculating & Generating Risk Framework...';

      try {
        const assessment = await apiClient.submitAssessment(payload);
        populateAssessmentData(assessment);
        switchView('dashboard');
      } catch (err) {
        console.error('Error submitting assessment:', err);
        alert('Assessment calculation failed. Please check form inputs.');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '🛡 Submit & Generate Risk Assessment';
      }
    });
  }

  // Load Demo Button inside wizard
  const wizardDemoBtn = document.getElementById('wizard-demo-btn');
  if (wizardDemoBtn) {
    wizardDemoBtn.addEventListener('click', loadDemoData);
  }
}

function goToWizardStep(stepNum) {
  if (stepNum < 1 || stepNum > 4) return;
  currentWizardStep = stepNum;

  // Update step indicators
  document.querySelectorAll('.wizard-step-item').forEach(item => {
    const s = parseInt(item.getAttribute('data-step'), 10);
    item.classList.remove('active', 'completed');
    if (s === stepNum) item.classList.add('active');
    else if (s < stepNum) item.classList.add('completed');
  });

  // Show step contents
  document.querySelectorAll('.wizard-step-content').forEach(content => {
    content.style.display = 'none';
  });
  const activeContent = document.getElementById(`wizard-step-${stepNum}`);
  if (activeContent) activeContent.style.display = 'block';

  // If entering review step, generate live summary
  if (stepNum === 4) {
    updateReviewSummary();
  }
}

function validateStep(step) {
  if (step === 1) {
    const name = document.getElementById('biz-name').value.trim();
    const ind = document.getElementById('biz-industry').value.trim();
    const emp = parseInt(document.getElementById('biz-employees').value, 10);
    const dev = parseInt(document.getElementById('biz-devices').value, 10);

    if (!name) { alert('Please enter Business Name.'); return false; }
    if (!ind) { alert('Please enter Industry.'); return false; }
    if (isNaN(emp) || emp < 1) { alert('Please enter a valid number of employees (minimum 1).'); return false; }
    if (isNaN(dev) || dev < 1) { alert('Please enter a valid number of devices (minimum 1).'); return false; }
  }
  return true;
}

/**
 * Dynamic Threat Sliders & Real-Time Calculation
 */
function initThreatSliders() {
  document.querySelectorAll('.threat-eval-item').forEach(card => {
    const threatId = card.getAttribute('data-threat-id');
    const lSlider = card.querySelector(`[data-param="likelihood"]`);
    const sSlider = card.querySelector(`[data-param="severity"]`);
    const iSlider = card.querySelector(`[data-param="impact"]`);

    const lVal = card.querySelector('.val-l');
    const sVal = card.querySelector('.val-s');
    const iVal = card.querySelector('.val-i');
    const scorePill = card.querySelector('.threat-score-pill');

    function updateLiveScore() {
      const l = parseInt(lSlider.value, 10);
      const s = parseInt(sSlider.value, 10);
      const i = parseInt(iSlider.value, 10);

      lVal.textContent = l;
      sVal.textContent = s;
      iVal.textContent = i;

      const score = l * s * i;
      scorePill.textContent = score;

      scorePill.className = 'threat-score-pill';
      if (score >= 101) scorePill.classList.add('badge-critical');
      else if (score >= 76) scorePill.classList.add('badge-very-high');
      else if (score >= 51) scorePill.classList.add('badge-high');
      else if (score >= 26) scorePill.classList.add('badge-moderate');
      else scorePill.classList.add('badge-low');
    }

    lSlider.addEventListener('input', updateLiveScore);
    sSlider.addEventListener('input', updateLiveScore);
    iSlider.addEventListener('input', updateLiveScore);
    updateLiveScore();
  });
}

function extractFormData() {
  const businessInfo = {
    businessName: document.getElementById('biz-name').value.trim(),
    industry: document.getElementById('biz-industry').value.trim(),
    employees: parseInt(document.getElementById('biz-employees').value, 10) || 1,
    devices: parseInt(document.getElementById('biz-devices').value, 10) || 1,
    locations: parseInt(document.getElementById('biz-locations').value, 10) || 1,
    usesCloud: document.getElementById('biz-cloud').checked,
    storesCustomerData: document.getElementById('biz-data').checked,
    hasRemoteEmployees: document.getElementById('biz-remote').checked
  };

  const controls = {};
  document.querySelectorAll('.control-item input[type="checkbox"]').forEach(cb => {
    controls[cb.getAttribute('data-control-id')] = cb.checked;
  });

  const threats = {};
  document.querySelectorAll('.threat-eval-item').forEach(card => {
    const tid = card.getAttribute('data-threat-id');
    threats[tid] = {
      likelihood: parseInt(card.querySelector(`[data-param="likelihood"]`).value, 10),
      severity: parseInt(card.querySelector(`[data-param="severity"]`).value, 10),
      impact: parseInt(card.querySelector(`[data-param="impact"]`).value, 10)
    };
  });

  return { businessInfo, controls, threats };
}

function updateReviewSummary() {
  const data = extractFormData();
  const revBiz = document.getElementById('rev-biz-summary');
  if (revBiz) {
    revBiz.innerHTML = `
      <strong>${data.businessInfo.businessName}</strong> (${data.businessInfo.industry})<br>
      Employees: ${data.businessInfo.employees} | Devices: ${data.businessInfo.devices} | Locations: ${data.businessInfo.locations}<br>
      Cloud: ${data.businessInfo.usesCloud ? 'Yes' : 'No'} | Customer PII: ${data.businessInfo.storesCustomerData ? 'Yes' : 'No'} | Remote: ${data.businessInfo.hasRemoteEmployees ? 'Yes' : 'No'}
    `;
  }

  let impCount = 0;
  Object.values(data.controls).forEach(v => { if (v) impCount += 1; });
  const revCtrl = document.getElementById('rev-ctrl-summary');
  if (revCtrl) {
    revCtrl.innerHTML = `
      Implemented Controls: <strong>${impCount} / 10</strong> (${impCount * 10}%)
    `;
  }
}

/**
 * Load Pre-configured Demo Data
 */
async function loadDemoData() {
  try {
    const demo = await apiClient.loadDemoAssessment();
    populateAssessmentData(demo);

    // Pre-fill form fields
    document.getElementById('biz-name').value = 'TechNova Solutions (DEMO DATA)';
    document.getElementById('biz-industry').value = 'IT Services';
    document.getElementById('biz-employees').value = 50;
    document.getElementById('biz-devices').value = 75;
    document.getElementById('biz-locations').value = 2;
    document.getElementById('biz-cloud').checked = true;
    document.getElementById('biz-data').checked = true;
    document.getElementById('biz-remote').checked = true;

    // Pre-fill controls
    const demoControls = {
      firewall: true, antivirus: true, mfa: false, backups: true,
      encryption: false, training: false, patching: true, access_control: true,
      monitoring: false, incident_response: false
    };
    Object.keys(demoControls).forEach(cid => {
      const cb = document.querySelector(`input[data-control-id="${cid}"]`);
      if (cb) cb.checked = demoControls[cid];
    });

    // Pre-fill threats
    const demoThreats = {
      phishing: [4, 4, 4],
      ransomware: [3, 5, 5],
      malware: [3, 3, 4],
      insider_threat: [2, 3, 3],
      data_breach: [4, 5, 4],
      weak_passwords: [4, 4, 4],
      ddos: [2, 3, 3],
      unpatched_software: [3, 3, 4],
      social_engineering: [4, 4, 4],
      unauthorized_access: [4, 4, 5]
    };
    Object.keys(demoThreats).forEach(tid => {
      const card = document.querySelector(`.threat-eval-item[data-threat-id="${tid}"]`);
      if (card) {
        const [l, s, i] = demoThreats[tid];
        card.querySelector(`[data-param="likelihood"]`).value = l;
        card.querySelector(`[data-param="severity"]`).value = s;
        card.querySelector(`[data-param="impact"]`).value = i;
        card.querySelector(`[data-param="likelihood"]`).dispatchEvent(new Event('input'));
      }
    });

    switchView('dashboard');
  } catch (err) {
    console.error('Error loading demo assessment:', err);
  }
}

/**
 * Populate UI with Assessment Results
 */
function populateAssessmentData(assessment) {
  currentAssessment = assessment;

  // Demo Banner Visibility
  const demoBanner = document.getElementById('demo-data-banner');
  if (demoBanner) {
    demoBanner.style.display = assessment.isDemo ? 'flex' : 'none';
  }

  // Dashboard KPI Values
  const overallScoreEl = document.getElementById('kpi-overall-score');
  const overallBadgeEl = document.getElementById('kpi-overall-badge');
  const postureScoreEl = document.getElementById('kpi-posture-score');
  const postureBadgeEl = document.getElementById('kpi-posture-badge');

  if (overallScoreEl) overallScoreEl.textContent = assessment.threatResults.overallScore;
  if (overallBadgeEl) {
    overallBadgeEl.textContent = assessment.threatResults.overallLevel;
    overallBadgeEl.className = `badge ${assessment.threatResults.overallBadgeClass}`;
  }

  if (postureScoreEl) postureScoreEl.textContent = `${assessment.controlResults.score}%`;
  if (postureBadgeEl) {
    postureBadgeEl.textContent = assessment.controlResults.postureLevel;
    postureBadgeEl.className = `badge ${assessment.controlResults.postureBadgeClass}`;
  }

  // Severity Counts
  const counts = assessment.threatResults.counts;
  document.getElementById('kpi-critical-count').textContent = counts.critical;
  document.getElementById('kpi-high-count').textContent = counts.high;
  document.getElementById('kpi-moderate-count').textContent = counts.moderate;
  document.getElementById('kpi-low-count').textContent = counts.low;

  // Render Sub-Views
  renderCharts(assessment);
  renderRiskMatrix(assessment.threatResults.threats);
  renderRiskRegister(assessment.threatResults.threats);
  renderNistFrameworkView(assessment.nistResults, assessment.controlResults);
  renderActionPlanView(assessment.mitigationPlan);
  renderReportView(assessment);
}

/**
 * Render Dynamic Charts with Chart.js
 */
function renderCharts(assessment) {
  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not loaded. Skipping chart rendering.');
    return;
  }

  // Destroy previous charts
  Object.values(charts).forEach(c => {
    if (c && typeof c.destroy === 'function') c.destroy();
  });
  charts = {};

  const counts = assessment.threatResults.counts;
  const threats = assessment.threatResults.threats;
  const nist = assessment.nistResults;
  const controls = assessment.controlResults;

  // 1. Doughnut: Risk Distribution
  const ctxDist = document.getElementById('chart-risk-distribution')?.getContext('2d');
  if (ctxDist) {
    charts.dist = new Chart(ctxDist, {
      type: 'doughnut',
      data: {
        labels: ['Critical (101-125)', 'Very High (76-100)', 'High (51-75)', 'Moderate (26-50)', 'Low (0-25)'],
        datasets: [{
          data: [counts.critical, counts.veryHigh, counts.high, counts.moderate, counts.low],
          backgroundColor: ['#dc2626', '#ef4444', '#f97316', '#f59e0b', '#10b981'],
          borderWidth: 2,
          borderColor: '#0f172a'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } }
        }
      }
    });
  }

  // 2. Horizontal Bar: Threat Scores Ranking
  const ctxRanking = document.getElementById('chart-threat-ranking')?.getContext('2d');
  if (ctxRanking) {
    charts.ranking = new Chart(ctxRanking, {
      type: 'bar',
      data: {
        labels: threats.map(t => t.name),
        datasets: [{
          label: 'Risk Score (0 - 125)',
          data: threats.map(t => t.score),
          backgroundColor: threats.map(t => t.riskColor),
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { max: 125, grid: { color: 'rgba(51, 65, 85, 0.4)' }, ticks: { color: '#94a3b8' } },
          y: { grid: { display: false }, ticks: { color: '#cbd5e1', font: { weight: 600 } } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // 3. Scatter: Likelihood vs Business Impact
  const ctxScatter = document.getElementById('chart-likelihood-impact')?.getContext('2d');
  if (ctxScatter) {
    charts.scatter = new Chart(ctxScatter, {
      type: 'bubble',
      data: {
        datasets: threats.map(t => ({
          label: t.name,
          data: [{ x: t.likelihood, y: t.impact, r: Math.max(6, Math.min(22, t.score / 6)) }],
          backgroundColor: t.riskColor + 'bb',
          borderColor: t.riskColor
        }))
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { min: 0.5, max: 5.5, title: { display: true, text: 'Likelihood (1 - 5)', color: '#94a3b8' }, ticks: { stepSize: 1, color: '#94a3b8' }, grid: { color: 'rgba(51, 65, 85, 0.4)' } },
          y: { min: 0.5, max: 5.5, title: { display: true, text: 'Business Impact (1 - 5)', color: '#94a3b8' }, ticks: { stepSize: 1, color: '#94a3b8' }, grid: { color: 'rgba(51, 65, 85, 0.4)' } }
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 10, font: { size: 10 } } }
        }
      }
    });
  }

  // 4. Radar: NIST CSF Maturity
  const ctxRadar = document.getElementById('chart-nist-radar')?.getContext('2d');
  if (ctxRadar) {
    const nistKeys = ['IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];
    const nistScores = nistKeys.map(k => nist[k]?.score || 0);

    charts.radar = new Chart(ctxRadar, {
      type: 'radar',
      data: {
        labels: nistKeys,
        datasets: [{
          label: 'NIST Maturity Score (%)',
          data: nistScores,
          backgroundColor: 'rgba(6, 182, 212, 0.25)',
          borderColor: '#06b6d4',
          pointBackgroundColor: '#38bdf8',
          pointBorderColor: '#ffffff',
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            min: 0,
            max: 100,
            ticks: { display: false },
            grid: { color: 'rgba(51, 65, 85, 0.5)' },
            angleLines: { color: 'rgba(51, 65, 85, 0.5)' },
            pointLabels: { color: '#e2e8f0', font: { size: 11, weight: 'bold' } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // 5. Controls Implementation Doughnut
  const ctxControls = document.getElementById('chart-controls-pie')?.getContext('2d');
  if (ctxControls) {
    charts.controls = new Chart(ctxControls, {
      type: 'doughnut',
      data: {
        labels: ['Implemented Controls', 'Missing Control Deficiencies'],
        datasets: [{
          data: [controls.implementedControls, controls.missingControls],
          backgroundColor: ['#10b981', '#dc2626'],
          borderWidth: 2,
          borderColor: '#0f172a'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } }
        }
      }
    });
  }
}

/**
 * 5x5 Interactive Risk Matrix
 */
function renderRiskMatrix(threats) {
  const container = document.getElementById('matrix-table-body');
  if (!container) return;
  container.innerHTML = '';

  // Severity / Impact Y-axis: 5 down to 1
  for (let s = 5; s >= 1; s--) {
    const row = document.createElement('tr');

    // Row Header (Severity Label)
    const rowHeader = document.createElement('th');
    const sLabels = { 5: '5 - Catastrophic', 4: '4 - Major', 3: '3 - Moderate', 2: '2 - Minor', 1: '1 - Negligible' };
    rowHeader.textContent = sLabels[s];
    rowHeader.style.whiteSpace = 'nowrap';
    row.appendChild(rowHeader);

    // Columns (Likelihood X-axis: 1 to 5)
    for (let l = 1; l <= 5; l++) {
      const cell = document.createElement('td');
      cell.className = 'matrix-cell';

      // Zone coloring heuristic based on (L * S * avg_impact)
      const baseProduct = l * s * 3; // normalized baseline product
      if (baseProduct >= 55 || (l >= 4 && s >= 4)) cell.classList.add('cell-critical');
      else if (baseProduct >= 35 || (l >= 3 && s >= 4)) cell.classList.add('cell-high');
      else if (baseProduct >= 20) cell.classList.add('cell-moderate');
      else cell.classList.add('cell-low');

      // Place matching threats into cell
      const matchingThreats = threats.filter(t => t.likelihood === l && (t.severity === s || t.impact === s));

      const chipContainer = document.createElement('div');
      chipContainer.className = 'cell-chip-container';

      matchingThreats.forEach(t => {
        const chip = document.createElement('span');
        chip.className = 'threat-chip';
        chip.style.borderColor = t.riskColor;
        chip.style.color = t.riskColor;
        chip.textContent = `${t.name} (${t.score})`;
        chip.title = `Click to view mitigation details for ${t.name}`;
        chip.addEventListener('click', (e) => {
          e.stopPropagation();
          showThreatModal(t);
        });
        chipContainer.appendChild(chip);
      });

      cell.appendChild(chipContainer);
      row.appendChild(cell);
    }

    container.appendChild(row);
  }
}

/**
 * Interactive Threat Modal Details
 */
function initModal() {
  const modal = document.getElementById('threat-detail-modal');
  const closeBtn = document.getElementById('modal-close-btn');

  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('active');
    });
  }
}

function showThreatModal(threat) {
  const modal = document.getElementById('threat-detail-modal');
  if (!modal) return;

  document.getElementById('modal-threat-title').textContent = threat.name;
  document.getElementById('modal-threat-score').textContent = threat.score;
  document.getElementById('modal-threat-badge').textContent = threat.riskLevel;
  document.getElementById('modal-threat-badge').className = `badge ${threat.badgeClass}`;

  document.getElementById('modal-threat-l').textContent = threat.likelihood;
  document.getElementById('modal-threat-s').textContent = threat.severity;
  document.getElementById('modal-threat-i').textContent = threat.impact;
  document.getElementById('modal-threat-nist').textContent = threat.nistCategory;

  document.getElementById('modal-threat-desc').textContent = threat.description || 'Standard SME Threat Profile';

  // Mitigations list
  const mitList = document.getElementById('modal-threat-mitigations');
  mitList.innerHTML = '';
  const mitigations = threat.commonMitigations || [
    'Enforce Multi-Factor Authentication',
    'Deploy Next-Generation Endpoint Protection',
    'Conduct staff cybersecurity awareness drills'
  ];
  mitigations.forEach(m => {
    const li = document.createElement('li');
    li.textContent = m;
    mitList.appendChild(li);
  });

  modal.classList.add('active');
}

/**
 * Risk Register Table with Search, Filter & Sort
 */
function renderRiskRegister(threats) {
  riskRegisterData = [...threats];
  applyRiskRegisterFilters();

  // Search Input
  const searchInput = document.getElementById('register-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', applyRiskRegisterFilters);
  }

  // Level Filter
  const levelSelect = document.getElementById('register-filter-level');
  if (levelSelect) {
    levelSelect.addEventListener('change', applyRiskRegisterFilters);
  }

  // NIST Filter
  const nistSelect = document.getElementById('register-filter-nist');
  if (nistSelect) {
    nistSelect.addEventListener('change', applyRiskRegisterFilters);
  }

  // Table Column Sort Headers
  document.querySelectorAll('[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.getAttribute('data-sort');
      if (sortDirection.column === col) {
        sortDirection.ascending = !sortDirection.ascending;
      } else {
        sortDirection.column = col;
        sortDirection.ascending = false;
      }
      applyRiskRegisterFilters();
    });
  });

  // Export Buttons
  const csvBtn = document.getElementById('export-csv-btn');
  if (csvBtn) csvBtn.addEventListener('click', exportRegisterCSV);

  const jsonBtn = document.getElementById('export-json-btn');
  if (jsonBtn) jsonBtn.addEventListener('click', exportRegisterJSON);
}

function applyRiskRegisterFilters() {
  const query = (document.getElementById('register-search-input')?.value || '').toLowerCase();
  const levelFilter = document.getElementById('register-filter-level')?.value || 'ALL';
  const nistFilter = document.getElementById('register-filter-nist')?.value || 'ALL';

  let filtered = riskRegisterData.filter(t => {
    const matchesSearch = t.name.toLowerCase().includes(query);
    const matchesLevel = levelFilter === 'ALL' || t.riskLevel.toUpperCase() === levelFilter;
    const matchesNist = nistFilter === 'ALL' || t.nistCategory === nistFilter;
    return matchesSearch && matchesLevel && matchesNist;
  });

  // Sorting
  const { column, ascending } = sortDirection;
  filtered.sort((a, b) => {
    let valA = a[column];
    let valB = b[column];
    if (typeof valA === 'string') valA = valA.toLowerCase();
    if (typeof valB === 'string') valB = valB.toLowerCase();
    if (valA < valB) return ascending ? -1 : 1;
    if (valA > valB) return ascending ? 1 : -1;
    return 0;
  });

  const tbody = document.getElementById('register-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  filtered.forEach(t => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${t.name}</strong></td>
      <td><span class="control-category-tag">${t.nistCategory}</span></td>
      <td>${t.likelihood}</td>
      <td>${t.severity}</td>
      <td>${t.impact}</td>
      <td><strong style="color: ${t.riskColor}; font-size: 1rem;">${t.score}</strong></td>
      <td><span class="badge ${t.badgeClass}">${t.riskLevel}</span></td>
      <td><span class="badge" style="background: rgba(255,255,255,0.1)">Priority ${t.priority}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="showThreatModalById('${t.id}')">
          🔍 View Mitigations
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.showThreatModalById = function(threatId) {
  if (!currentAssessment) return;
  const threat = currentAssessment.threatResults.threats.find(t => t.id === threatId);
  if (threat) showThreatModal(threat);
};

function exportRegisterCSV() {
  if (!currentAssessment) return;
  let csv = 'Threat ID,Threat Name,NIST Function,Likelihood,Severity,Business Impact,Risk Score,Risk Level,Priority\n';
  currentAssessment.threatResults.threats.forEach(t => {
    csv += `"${t.id}","${t.name}","${t.nistCategory}",${t.likelihood},${t.severity},${t.impact},${t.score},"${t.riskLevel}",${t.priority}\n`;
  });
  downloadBlob(csv, `sme_risk_register_${Date.now()}.csv`, 'text/csv');
}

function exportRegisterJSON() {
  if (!currentAssessment) return;
  const jsonStr = JSON.stringify(currentAssessment, null, 2);
  downloadBlob(jsonStr, `sme_assessment_${Date.now()}.json`, 'application/json');
}

function downloadBlob(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Dedicated NIST Framework 5-Pillar View
 */
function renderNistFrameworkView(nist, controls) {
  const container = document.getElementById('nist-details-container');
  if (!container || !nist) return;
  container.innerHTML = '';

  const functions = ['IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];
  const fnMeta = {
    IDENTIFY: { title: '1. Identify (ID)', desc: 'Develop organizational understanding to manage cybersecurity risk to systems, people, assets, data, and capabilities.' },
    PROTECT: { title: '2. Protect (PR)', desc: 'Develop and implement appropriate safeguards to ensure delivery of critical services and contain security incidents.' },
    DETECT: { title: '3. Detect (DE)', desc: 'Develop and implement appropriate activities to identify the occurrence of a cybersecurity event promptly.' },
    RESPOND: { title: '4. Respond (RS)', desc: 'Develop and implement appropriate activities to take action regarding a detected cybersecurity incident.' },
    RECOVER: { title: '5. Recover (RC)', desc: 'Develop and implement appropriate activities to maintain plans for resilience and to restore capabilities or services impaired.' }
  };

  functions.forEach(fn => {
    const data = nist[fn] || { score: 50, maturityLevel: 'Tier 2 (Risk Informed)' };
    const meta = fnMeta[fn];
    const card = document.createElement('div');
    card.className = 'threat-card';
    card.innerHTML = `
      <div class="threat-card-header">
        <h3 style="color: #38bdf8;">${meta.title}</h3>
        <span class="badge ${data.score >= 70 ? 'badge-low' : data.score >= 40 ? 'badge-moderate' : 'badge-critical'}">
          ${data.score}% Score
        </span>
      </div>
      <p class="threat-card-desc" style="margin-bottom: 1rem;">${meta.desc}</p>
      <div style="background: rgba(15,23,42,0.8); padding: 0.85rem; border-radius: 6px; font-size: 0.85rem;">
        <div>Maturity Tier: <strong>${data.maturityLevel}</strong></div>
        <div style="margin-top: 0.35rem; color: #94a3b8;">Controls Implemented: <strong>${data.controlCoverage || 'N/A'}</strong></div>
      </div>
    `;
    container.appendChild(card);
  });
}

/**
 * Priority Action Plan View
 */
function renderActionPlanView(mitigationPlan) {
  const container = document.getElementById('action-plan-container');
  if (!container || !mitigationPlan) return;
  container.innerHTML = '';

  const tiers = [
    { priority: 1, title: 'Priority 1: Critical Risks & Immediate Deficiencies', class: 'action-p1', badge: 'badge-critical' },
    { priority: 2, title: 'Priority 2: Very High Risks & Essential Safeguards', class: 'action-p2', badge: 'badge-very-high' },
    { priority: 3, title: 'Priority 3: High Risks & Robust Security Baseline', class: 'action-p3', badge: 'badge-high' },
    { priority: 4, title: 'Priority 4: Moderate Risks & Defense-in-Depth', class: 'action-p4', badge: 'badge-moderate' },
    { priority: 5, title: 'Priority 5: Low Risks & Proactive Maintenance', class: 'action-p5', badge: 'badge-low' }
  ];

  tiers.forEach(tier => {
    const items = mitigationPlan.planItems.filter(i => i.priority === tier.priority);
    if (items.length === 0) return;

    const group = document.createElement('div');
    group.className = 'plan-priority-group';

    const header = document.createElement('div');
    header.className = 'priority-header';
    header.innerHTML = `
      <h3>${tier.title}</h3>
      <span class="badge ${tier.badge}">${items.length} Action Items</span>
    `;
    group.appendChild(header);

    items.forEach(item => {
      const card = document.createElement('div');
      card.className = `action-card ${tier.class}`;
      card.innerHTML = `
        <div class="action-card-header">
          <div class="action-threat-name">${item.threatName}</div>
          <div class="action-meta">
            <span class="control-category-tag">${item.nistFunction}</span>
            <span class="badge" style="background: rgba(255,255,255,0.1)">⏱ ${item.suggestedTimeframe}</span>
          </div>
        </div>
        <div class="action-problem"><strong>Vulnerability / Risk:</strong> ${item.problem}</div>
        <div class="action-recommendation"><strong>Recommended Action:</strong> ${item.action}</div>
        <div class="action-benefit"><strong>Expected Business Benefit:</strong> ${item.expectedBenefit}</div>
      `;
      group.appendChild(card);
    });

    container.appendChild(group);
  });
}

/**
 * Report View Formatter
 */
function renderReportView(assessment) {
  const b = assessment.businessInfo;
  const t = assessment.threatResults;
  const c = assessment.controlResults;

  document.getElementById('rep-biz-name').textContent = b.businessName;
  document.getElementById('rep-industry').textContent = b.industry;
  document.getElementById('rep-employees').textContent = b.employees;
  document.getElementById('rep-devices').textContent = b.devices;
  document.getElementById('rep-locations').textContent = b.locations;
  document.getElementById('rep-date').textContent = new Date(assessment.createdAt).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });

  document.getElementById('rep-overall-score').textContent = t.overallScore;
  document.getElementById('rep-overall-level').textContent = t.overallLevel;
  document.getElementById('rep-posture-score').textContent = `${c.score}% (${c.postureLevel})`;

  // Populate Report Table
  const tableBody = document.getElementById('rep-table-body');
  if (tableBody) {
    tableBody.innerHTML = '';
    t.threats.forEach(th => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${th.name}</strong></td>
        <td>${th.nistCategory}</td>
        <td>${th.likelihood}</td>
        <td>${th.severity}</td>
        <td>${th.impact}</td>
        <td><strong>${th.score}</strong></td>
        <td>${th.riskLevel}</td>
        <td>Priority ${th.priority}</td>
      `;
      tableBody.appendChild(tr);
    });
  }
}
