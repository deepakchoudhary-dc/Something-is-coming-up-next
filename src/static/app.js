/**
 * AI Security Gateway - Frontend Application Controller
 */

// Application State
const STATE = {
    activeTab: 'overview',
    policies: {},
    activePolicyName: 'input_validation',
    hitlRequests: {},
    activeHitlId: null,
    logs: [],
    logsPage: 0,
    logsLimit: 12,
    logsSearch: '',
    logsAction: '',
    redteamPayloads: [],
    isScanning: false,
    hitlPollInterval: null
};

// DOM Elements
const DOM = {
    navItems: document.querySelectorAll('.nav-menu .nav-item'),
    tabViews: document.querySelectorAll('.tab-view'),
    tabTitle: document.getElementById('tab-title'),
    tabSubtitle: document.getElementById('tab-subtitle'),
    refreshBtn: document.getElementById('refresh-data-btn'),
    hitlBadge: document.getElementById('hitl-badge'),
    
    // Overview elements
    statTotalProcessed: document.getElementById('stat-total-processed'),
    statTotalBlocked: document.getElementById('stat-total-blocked'),
    statBlockRate: document.getElementById('stat-block-rate'),
    statPendingHitl: document.getElementById('stat-pending-hitl'),
    statRedteamScore: document.getElementById('stat-redteam-score'),
    statRedteamRate: document.getElementById('stat-redteam-rate'),
    recentAlertsTbody: document.getElementById('recent-alerts-tbody'),
    viewAllLogsShortcut: document.getElementById('view-all-logs-shortcut'),
    timelineChartContainer: document.getElementById('timeline-chart-container'),
    distributionChartContainer: document.getElementById('distribution-chart-container'),
    
    // Policy elements
    policyNavs: document.querySelectorAll('.policy-tab-nav'),
    policyFormTitle: document.getElementById('policy-form-title'),
    policyFormDesc: document.getElementById('policy-form-desc'),
    policyFieldsContainer: document.getElementById('policy-fields-container'),
    policyEnabledToggle: document.getElementById('policy-enabled-toggle'),
    savePolicyBtn: document.getElementById('save-policy-btn'),
    policySaveStatus: document.getElementById('policy-save-status'),
    
    // HITL elements
    hitlCountLabel: document.getElementById('hitl-count-label'),
    hitlRequestsList: document.getElementById('hitl-requests-list'),
    hitlDetailView: document.getElementById('hitl-detail-view'),
    hitlDetailsBody: document.getElementById('hitl-details-body'),
    hitlApproveBtn: document.getElementById('hitl-approve-btn'),
    hitlDenyBtn: document.getElementById('hitl-deny-btn'),
    
    // Logs elements
    logsTbody: document.getElementById('logs-tbody'),
    logsSearch: document.getElementById('logs-search'),
    logsFilterAction: document.getElementById('logs-filter-action'),
    paginationInfoLabel: document.getElementById('pagination-info-label'),
    paginationPrev: document.getElementById('pagination-prev'),
    paginationNext: document.getElementById('pagination-next'),
    logDetailModal: document.getElementById('log-detail-modal'),
    closeModalBtn: document.getElementById('close-modal-btn'),
    logModalBody: document.getElementById('log-modal-body'),
    
    // Red-Teaming elements
    runRedteamScanBtn: document.getElementById('run-redteam-scan-btn'),
    scanProgressArea: document.getElementById('scan-progress-area'),
    scanProgressFill: document.getElementById('scan-progress-fill'),
    scanProgressStatus: document.getElementById('scan-progress-status'),
    scanProgressPercent: document.getElementById('scan-progress-percent'),
    scanReportContainer: document.getElementById('scan-report-container'),
    reportPosture: document.getElementById('report-posture'),
    reportBlocked: document.getElementById('report-blocked'),
    reportBypassed: document.getElementById('report-bypassed'),
    reportDuration: document.getElementById('report-duration'),
    redteamReportTbody: document.getElementById('redteam-report-tbody'),
    payloadsRegistryList: document.getElementById('payloads-registry-list'),
    
    // Playground elements
    playgroundForm: document.getElementById('playground-form'),
    playgroundSubmitBtn: document.getElementById('playground-submit-btn'),
    playPrompt: document.getElementById('play-prompt'),
    playSystemPrompt: document.getElementById('play-system-prompt'),
    playRetrievedContext: document.getElementById('play-retrieved-context'),
    playUserId: document.getElementById('play-user-id'),
    playRole: document.getElementById('play-role'),
    playContext: document.getElementById('play-context'),
    playExecute: document.getElementById('play-execute'),
    
    stepSanitize: document.getElementById('step-sanitize'),
    stepContext: document.getElementById('step-context'),
    stepClassify: document.getElementById('step-classify'),
    stepPolicy: document.getElementById('step-policy'),
    stepSandbox: document.getElementById('step-sandbox'),
    stepLeakage: document.getElementById('step-leakage'),
    stepOutput: document.getElementById('step-output'),
    connectorSandbox: document.getElementById('connector-sandbox'),
    
    playgroundResultCard: document.getElementById('playground-result-card'),
    playVerdictBadge: document.getElementById('play-verdict-badge'),
    playRiskScore: document.getElementById('play-risk-score'),
    playDuration: document.getElementById('play-duration'),
    playSandboxBlock: document.getElementById('play-sandbox-block'),
    playSandboxOutput: document.getElementById('play-sandbox-output'),
    playResponseText: document.getElementById('play-response-text'),
    playAnomaliesBlock: document.getElementById('play-anomalies-block'),
    playAnomaliesList: document.getElementById('play-anomalies-list')
};

// Initial setup
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initOverview();
    initPolicies();
    initHITL();
    initLogs();
    initRedTeaming();
    initPlayground();
    
    // Sync all statistics initially
    syncAllData();
    
    // Periodically poll for pending HITL requests (every 5 seconds)
    STATE.hitlPollInterval = setInterval(pollPendingHITL, 5000);
});

// Sync data
function syncAllData() {
    fetchStats();
    fetchPolicies();
    pollPendingHITL();
    if (STATE.activeTab === 'logs') {
        fetchLogs();
    }
}

// -----------------------------------------------------
// NAVIGATION HUB
// -----------------------------------------------------
function initNavigation() {
    DOM.navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tabName = item.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
    
    DOM.refreshBtn.addEventListener('click', () => {
        DOM.refreshBtn.classList.add('fa-spin');
        syncAllData();
        setTimeout(() => DOM.refreshBtn.classList.remove('fa-spin'), 600);
    });

    if (DOM.viewAllLogsShortcut) {
        DOM.viewAllLogsShortcut.addEventListener('click', () => {
            switchTab('logs');
        });
    }
}

function switchTab(tabName) {
    STATE.activeTab = tabName;
    
    // Update active tab buttons
    DOM.navItems.forEach(item => {
        if (item.getAttribute('data-tab') === tabName) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Update active views
    DOM.tabViews.forEach(view => {
        if (view.id === `view-${tabName}`) {
            view.classList.add('active');
        } else {
            view.classList.remove('active');
        }
    });

    // Update headers
    const titleMap = {
        overview: { title: 'Security Overview', sub: 'Real-time gateway threat telemetry' },
        policies: { title: 'Security Policies', sub: 'Configure filter boundaries and rules' },
        hitl: { title: 'HITL Review Panel', sub: 'Authorize or deny high-risk executions' },
        logs: { title: 'Transaction Auditing', sub: 'Full request/response trace logs' },
        redteaming: { title: 'Red-Teaming Scan', sub: 'Automated policy vulnerability suite' },
        playground: { title: 'Gateway Playground', sub: 'Inspect request parsing pipeline' }
    };

    DOM.tabTitle.innerText = titleMap[tabName].title;
    DOM.tabSubtitle.innerText = titleMap[tabName].sub;

    // View-specific loaders
    if (tabName === 'overview') {
        fetchStats();
    } else if (tabName === 'policies') {
        renderActivePolicyForm();
    } else if (tabName === 'hitl') {
        loadHITLList();
    } else if (tabName === 'logs') {
        fetchLogs();
    } else if (tabName === 'redteaming') {
        fetchRedteamPayloads();
    }
}

// -----------------------------------------------------
// 1. OVERVIEW & ANALYTICS VIEWS
// -----------------------------------------------------
function initOverview() {
    // Intentionally empty. Triggered on navigation
}

async function fetchStats() {
    try {
        const res = await fetch('/api/v1/monitoring/stats');
        const data = await res.json();
        
        DOM.statTotalProcessed.innerText = data.total_requests;
        DOM.statTotalBlocked.innerText = data.blocked_requests;
        DOM.statBlockRate.innerText = `${data.block_rate}% block rate`;
        DOM.statPendingHitl.innerText = data.pending_hitl;
        
        // Render charts using SVGs
        renderTimelineChart(data.activity_timeline);
        renderDistributionChart(data.action_distribution);
        
        // Fetch recent incident list
        fetchRecentIncidents();
    } catch (e) {
        console.error("Failed to load stats", e);
    }
}

async function fetchRecentIncidents() {
    try {
        const res = await fetch('/api/v1/monitoring/logs?limit=5');
        const logs = await res.json();
        
        let html = '';
        const flaggedLogs = logs.filter(l => l.flagged || l.action_taken !== 'allowed');
        
        if (flaggedLogs.length === 0) {
            DOM.recentAlertsTbody.innerHTML = `<tr><td colspan="5" class="table-empty">No flagged security threats detected.</td></tr>`;
            return;
        }

        flaggedLogs.forEach(l => {
            const date = new Date(l.timestamp).toLocaleTimeString();
            const actionBadgeClass = getActionBadgeClass(l.action_taken);
            const scoreClass = l.risk_score > 0.75 ? 'high' : l.risk_score > 0.4 ? 'medium' : 'low';
            
            html += `
                <tr>
                    <td>${date}</td>
                    <td><code>${escapeHtml(l.user_id)}</code></td>
                    <td title="${escapeHtml(l.prompt)}">${escapeHtml(truncateString(l.prompt, 45))}</td>
                    <td><span class="badge-risk ${scoreClass}">${l.risk_score.toFixed(2)}</span></td>
                    <td><span class="badge-status ${actionBadgeClass}">${l.action_taken}</span></td>
                </tr>
            `;
        });

        DOM.recentAlertsTbody.innerHTML = html;
    } catch (e) {
        console.error("Failed to fetch recent incidents", e);
    }
}

function renderTimelineChart(timeline) {
    if (!timeline || timeline.length === 0) return;
    
    const containerWidth = DOM.timelineChartContainer.clientWidth || 500;
    const containerHeight = 220;
    
    // Draw SVG Line Chart
    const maxVal = Math.max(...timeline.map(t => t.total), 5);
    const padding = { top: 20, right: 20, bottom: 30, left: 35 };
    const chartW = containerWidth - padding.left - padding.right;
    const chartH = containerHeight - padding.top - padding.bottom;
    
    let pathData = '';
    let flaggedPathData = '';
    let gridLinesHtml = '';
    let xLabelsHtml = '';
    let yLabelsHtml = '';
    
    // Draw Y axis grids & labels
    const ySegments = 4;
    for (let i = 0; i <= ySegments; i++) {
        const yVal = Math.round((maxVal / ySegments) * i);
        const yPos = padding.top + chartH - (chartH / ySegments) * i;
        gridLinesHtml += `<line class="chart-grid-line" x1="${padding.left}" y1="${yPos}" x2="${padding.left + chartW}" y2="${yPos}" />`;
        yLabelsHtml += `<text class="chart-text" x="${padding.left - 8}" y="${yPos + 3}" text-anchor="end">${yVal}</text>`;
    }

    // Generate path points
    const stepX = chartW / (timeline.length - 1);
    timeline.forEach((point, idx) => {
        const x = padding.left + idx * stepX;
        
        // Total queries position
        const yTotal = padding.top + chartH - (point.total / maxVal) * chartH;
        pathData += (idx === 0 ? 'M' : 'L') + ` ${x} ${yTotal}`;
        
        // Flagged queries position
        const yFlagged = padding.top + chartH - (point.flagged / maxVal) * chartH;
        flaggedPathData += (idx === 0 ? 'M' : 'L') + ` ${x} ${yFlagged}`;
        
        // X label (Day short)
        xLabelsHtml += `<text class="chart-text" x="${x}" y="${containerHeight - 8}" text-anchor="middle">${point.label}</text>`;
    });

    const svgHtml = `
        <svg class="chart-svg" width="100%" height="${containerHeight}">
            <defs>
                <linearGradient id="chart-gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#00d2ff" stop-opacity="0.4"/>
                    <stop offset="100%" stop-color="#00d2ff" stop-opacity="0"/>
                </linearGradient>
            </defs>
            ${gridLinesHtml}
            <!-- Shaded Area total -->
            <path d="${pathData} L ${padding.left + chartW} ${padding.top + chartH} L ${padding.left} ${padding.top + chartH} Z" class="chart-area" />
            <!-- Line total -->
            <path d="${pathData}" class="chart-line" />
            <!-- Line flagged -->
            <path d="${flaggedPathData}" class="chart-line-flagged" />
            ${xLabelsHtml}
            ${yLabelsHtml}
        </svg>
    `;
    
    DOM.timelineChartContainer.innerHTML = svgHtml;
}

function renderDistributionChart(dist) {
    if (!dist) return;
    
    const containerWidth = DOM.distributionChartContainer.clientWidth || 250;
    const containerHeight = 220;
    const centerX = containerWidth / 2;
    const centerY = containerHeight / 2 - 10;
    const radius = 68;
    const innerRadius = 45;
    
    // Action categories
    const actions = [
        { label: 'Allowed', val: dist.allowed || 0, color: '#00e676' },
        { label: 'Blocked Input', val: dist.blocked_input || 0, color: '#ff3b6b' },
        { label: 'Blocked Output', val: dist.blocked_output || 0, color: '#ff9100' },
        { label: 'HITL Approved', val: dist.hitl_approved || 0, color: '#00d2ff' },
        { label: 'HITL Denied', val: dist.hitl_denied || 0, color: '#b388ff' }
    ];
    
    const total = actions.reduce((sum, current) => sum + current.val, 0);
    
    if (total === 0) {
        DOM.distributionChartContainer.innerHTML = `<div class="chart-placeholder">No action logs found.</div>`;
        return;
    }
    
    let currentAngle = 0;
    let pathsHtml = '';
    let legendHtml = '';
    
    actions.forEach(a => {
        if (a.val === 0) return;
        
        const percentage = a.val / total;
        const angle = percentage * 360;
        
        // Calculate arc coordinates
        const startRad = (currentAngle - 90) * Math.PI / 180;
        const endRad = (currentAngle + angle - 90) * Math.PI / 180;
        
        const x1Outer = centerX + radius * Math.cos(startRad);
        const y1Outer = centerY + radius * Math.sin(startRad);
        const x2Outer = centerX + radius * Math.cos(endRad);
        const y2Outer = centerY + radius * Math.sin(endRad);
        
        const x1Inner = centerX + innerRadius * Math.cos(startRad);
        const y1Inner = centerY + innerRadius * Math.sin(startRad);
        const x2Inner = centerX + innerRadius * Math.cos(endRad);
        const y2Inner = centerY + innerRadius * Math.sin(endRad);
        
        const largeArc = angle > 180 ? 1 : 0;
        
        const d = `
            M ${x1Outer} ${y1Outer}
            A ${radius} ${radius} 0 ${largeArc} 1 ${x2Outer} ${y2Outer}
            L ${x2Inner} ${y2Inner}
            A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${x1Inner} ${y1Inner}
            Z
        `;
        
        pathsHtml += `<path d="${d}" fill="${a.color}" stroke="#121721" stroke-width="1" />`;
        
        currentAngle += angle;
    });

    const svgHtml = `
        <svg class="chart-svg" width="100%" height="${containerHeight}">
            ${pathsHtml}
            <!-- Center overlay text -->
            <circle cx="${centerX}" cy="${centerY}" r="${innerRadius - 2}" fill="#161c29" />
            <text x="${centerX}" y="${centerY - 4}" text-anchor="middle" font-weight="700" font-size="14" fill="#fff">${total}</text>
            <text x="${centerX}" y="${centerY + 10}" text-anchor="middle" font-size="9" fill="#6b7280" font-weight="600" style="letter-spacing: 0.5px; text-transform: uppercase;">Actions</text>
        </svg>
    `;
    
    DOM.distributionChartContainer.innerHTML = svgHtml;
}

// -----------------------------------------------------
// 2. SECURITY POLICY CONTROL HUB
// -----------------------------------------------------
function initPolicies() {
    DOM.policyNavs.forEach(nav => {
        nav.addEventListener('click', () => {
            DOM.policyNavs.forEach(n => n.classList.remove('active'));
            nav.classList.add('active');
            
            STATE.activePolicyName = nav.getAttribute('data-policy');
            renderActivePolicyForm();
        });
    });

    DOM.savePolicyBtn.addEventListener('click', saveActivePolicy);
}

async function fetchPolicies() {
    try {
        const res = await fetch('/api/v1/policies');
        STATE.policies = await res.json();
        
        // If we are currently displaying Policy page, refresh inputs
        if (STATE.activeTab === 'policies') {
            renderActivePolicyForm();
        }
    } catch (e) {
        console.error("Failed to fetch policies", e);
    }
}

function renderActivePolicyForm() {
    const policy = STATE.policies[STATE.activePolicyName];
    if (!policy) {
        DOM.policyFieldsContainer.innerHTML = `<div class="table-empty">Loading policy parameters...</div>`;
        return;
    }

    // Configure titles
    DOM.policyFormTitle.innerText = policy.name;
    DOM.policyFormDesc.innerText = policy.description;
    DOM.policyEnabledToggle.checked = policy.enabled;

    let html = '';
    const rules = policy.rules;

    if (STATE.activePolicyName === 'input_validation') {
        html = `
            <div class="form-group">
                <label for="rule-min-length">Min prompt characters:</label>
                <input type="number" id="rule-min-length" value="${rules.min_length || 1}">
            </div>
            <div class="form-group">
                <label for="rule-max-length">Max prompt characters:</label>
                <input type="number" id="rule-max-length" value="${rules.max_length || 10000}">
            </div>
            <div class="form-group">
                <label for="rule-block-patterns">Prohibited prompt patterns (One per line):</label>
                <textarea id="rule-block-patterns" rows="5">${(rules.block_patterns || []).join('\n')}</textarea>
            </div>
        `;
    } else if (STATE.activePolicyName === 'content_filtering') {
        html = `
            <div class="form-group">
                <label for="rule-toxicity-threshold">Toxicity sensitivity threshold (0.0 to 1.0):</label>
                <input type="number" id="rule-toxicity-threshold" step="0.05" min="0" max="1" value="${rules.toxicity_threshold || 0.7}">
            </div>
            <div class="form-group">
                <label for="rule-block-categories">Violent/Harmful Block Categories (Comma-separated):</label>
                <input type="text" id="rule-block-categories" value="${(rules.block_categories || []).join(', ')}">
            </div>
            <div class="form-group">
                <label for="rule-allow-domains">Approved Knowledge domains (Comma-separated):</label>
                <input type="text" id="rule-allow-domains" value="${(rules.allow_domains || []).join(', ')}">
            </div>
        `;
    } else if (STATE.activePolicyName === 'rate_limiting') {
        html = `
            <div class="form-group">
                <label for="rule-rpm">Max requests per minute:</label>
                <input type="number" id="rule-rpm" value="${rules.requests_per_minute || 60}">
            </div>
            <div class="form-group">
                <label for="rule-rph">Max requests per hour:</label>
                <input type="number" id="rule-rph" value="${rules.requests_per_hour || 1000}">
            </div>
            <div class="form-group">
                <label for="rule-burst">Burst client allocation limit:</label>
                <input type="number" id="rule-burst" value="${rules.burst_limit || 10}">
            </div>
        `;
    } else if (STATE.activePolicyName === 'user_access') {
        html = `
            <div class="form-group">
                <label>Access Roles Permissions Configuration:</label>
                <textarea id="rule-roles-json" rows="8" style="font-family: monospace;">${JSON.stringify(rules.roles || {}, null, 2)}</textarea>
            </div>
        `;
    }

    DOM.policyFieldsContainer.innerHTML = html;
}

async function saveActivePolicy() {
    const policy = STATE.policies[STATE.activePolicyName];
    if (!policy) return;

    DOM.policySaveStatus.className = 'save-status';
    DOM.policySaveStatus.innerText = 'Saving policy changes...';

    // Compile modified values
    const updatedRules = {};
    
    try {
        if (STATE.activePolicyName === 'input_validation') {
            updatedRules.min_length = parseInt(document.getElementById('rule-min-length').value);
            updatedRules.max_length = parseInt(document.getElementById('rule-max-length').value);
            updatedRules.block_patterns = document.getElementById('rule-block-patterns').value
                .split('\n')
                .map(p => p.trim())
                .filter(p => p.length > 0);
        } else if (STATE.activePolicyName === 'content_filtering') {
            updatedRules.toxicity_threshold = parseFloat(document.getElementById('rule-toxicity-threshold').value);
            updatedRules.block_categories = document.getElementById('rule-block-categories').value
                .split(',')
                .map(c => c.trim())
                .filter(c => c.length > 0);
            updatedRules.allow_domains = document.getElementById('rule-allow-domains').value
                .split(',')
                .map(d => d.trim())
                .filter(d => d.length > 0);
        } else if (STATE.activePolicyName === 'rate_limiting') {
            updatedRules.requests_per_minute = parseInt(document.getElementById('rule-rpm').value);
            updatedRules.requests_per_hour = parseInt(document.getElementById('rule-rph').value);
            updatedRules.burst_limit = parseInt(document.getElementById('rule-burst').value);
        } else if (STATE.activePolicyName === 'user_access') {
            const rawJson = document.getElementById('rule-roles-json').value;
            updatedRules.roles = JSON.parse(rawJson);
        }

        const payload = {
            policies: {
                [STATE.activePolicyName]: {
                    description: policy.description,
                    enabled: DOM.policyEnabledToggle.checked,
                    rules: updatedRules
                }
            }
        };

        const res = await fetch('/api/v1/policies', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const status = await res.json();
        
        if (status.updated && status.updated.length > 0) {
            DOM.policySaveStatus.className = 'save-status success';
            DOM.policySaveStatus.innerText = 'Policy updated successfully!';
            
            // Sync state local
            fetchPolicies();
        } else {
            DOM.policySaveStatus.className = 'save-status error';
            DOM.policySaveStatus.innerText = `Update failed: ${status.message || 'Unknown error'}`;
        }

    } catch (e) {
        DOM.policySaveStatus.className = 'save-status error';
        DOM.policySaveStatus.innerText = `Format Error: ${e.message}`;
    }

    setTimeout(() => {
        DOM.policySaveStatus.innerText = '';
    }, 4000);
}

// -----------------------------------------------------
// 3. HUMAN-IN-THE-LOOP (HITL) WORKFLOW
// -----------------------------------------------------
function initHITL() {
    DOM.hitlApproveBtn.addEventListener('click', () => handleHITLDecision(true));
    DOM.hitlDenyBtn.addEventListener('click', () => handleHITLDecision(false));
}

async function pollPendingHITL() {
    try {
        const res = await fetch('/api/v1/hitl/pending');
        STATE.hitlRequests = await res.json();
        
        const count = Object.keys(STATE.hitlRequests).length;
        
        // Update badge counts in menu sidebar
        if (count > 0) {
            DOM.hitlBadge.innerText = count;
            DOM.hitlBadge.style.display = 'block';
        } else {
            DOM.hitlBadge.style.display = 'none';
        }

        if (STATE.activeTab === 'hitl') {
            loadHITLList();
        }
    } catch (e) {
        console.error("Failed to poll HITL pending requests", e);
    }
}

function loadHITLList() {
    const listContainer = DOM.hitlRequestsList;
    const reqs = Object.values(STATE.hitlRequests);

    DOM.hitlCountLabel.innerText = `${reqs.length} pending`;

    if (reqs.length === 0) {
        listContainer.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-check"></i>
                <h3>Queue Cleared</h3>
                <p>No high-risk requests are awaiting review.</p>
            </div>
        `;
        DOM.hitlDetailView.style.display = 'none';
        STATE.activeHitlId = null;
        return;
    }

    let html = '';
    reqs.forEach(r => {
        const date = new Date(r.timestamp).toLocaleTimeString();
        const activeClass = STATE.activeHitlId === r.id ? 'active' : '';
        
        html += `
            <div class="hitl-card ${activeClass}" onclick="selectHITLRequest('${r.id}')">
                <div class="hitl-card-header">
                    <span>User: ${escapeHtml(r.user_id)}</span>
                    <time>${date}</time>
                </div>
                <p>${escapeHtml(r.prompt)}</p>
            </div>
        `;
    });

    listContainer.innerHTML = html;

    // If there is an active item but it's no longer in queue, hide detail view
    if (STATE.activeHitlId && !STATE.hitlRequests[STATE.activeHitlId]) {
        STATE.activeHitlId = null;
        DOM.hitlDetailView.style.display = 'none';
    }

    // Auto-select the first request if none is selected
    if (!STATE.activeHitlId && reqs.length > 0) {
        selectHITLRequest(reqs[0].id);
    }
}

window.selectHITLRequest = function(id) {
    STATE.activeHitlId = id;
    
    // Highlight list card
    const cards = DOM.hitlRequestsList.querySelectorAll('.hitl-card');
    cards.forEach(c => {
        c.classList.remove('active');
    });
    
    // Read list item details
    const req = STATE.hitlRequests[id];
    if (!req) return;

    // Rerender details
    DOM.hitlDetailView.style.display = 'flex';
    
    const formattedTime = new Date(req.timestamp).toLocaleString();
    DOM.hitlDetailsBody.innerHTML = `
        <div class="detail-section">
            <h4>Request Context prompt</h4>
            <p>${escapeHtml(req.prompt)}</p>
        </div>
        <div class="detail-meta-grid">
            <div class="meta-box">
                <span>Sender User ID</span>
                <strong><code>${escapeHtml(req.user_id)}</code></strong>
            </div>
            <div class="meta-box">
                <span>Model Target</span>
                <strong><code>${escapeHtml(req.model)}</code></strong>
            </div>
            <div class="meta-box">
                <span>System Timestamp</span>
                <strong>${formattedTime}</strong>
            </div>
            <div class="meta-box">
                <span>Request ID</span>
                <strong><code>${escapeHtml(req.id)}</code></strong>
            </div>
        </div>
        ${req.context ? `
            <div class="detail-section" style="margin-top: 10px;">
                <h4>Payload Metadata Context</h4>
                <pre>${escapeHtml(req.context)}</pre>
            </div>
        ` : ''}
    `;
};

async function handleHITLDecision(approved) {
    if (!STATE.activeHitlId) return;
    
    const id = STATE.activeHitlId;
    
    try {
        const res = await fetch(`/api/v1/hitl/approve/${id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved: approved, admin_name: 'Admin Panel' })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            // Remove locally and redraw
            delete STATE.hitlRequests[id];
            STATE.activeHitlId = null;
            
            // Reload list and badge
            pollPendingHITL();
        } else {
            alert(`Approval failed: ${data.detail || 'Unknown error'}`);
        }
    } catch (e) {
        console.error("Error submitting decision", e);
    }
}

// -----------------------------------------------------
// 4. AUDIT & LOGS BROWSER
// -----------------------------------------------------
function initLogs() {
    DOM.logsSearch.addEventListener('input', () => {
        STATE.logsSearch = DOM.logsSearch.value;
        STATE.logsPage = 0;
        fetchLogs();
    });
    
    DOM.logsFilterAction.addEventListener('change', () => {
        STATE.logsAction = DOM.logsFilterAction.value;
        STATE.logsPage = 0;
        fetchLogs();
    });

    DOM.paginationPrev.addEventListener('click', () => {
        if (STATE.logsPage > 0) {
            STATE.logsPage--;
            fetchLogs();
        }
    });

    DOM.paginationNext.addEventListener('click', () => {
        STATE.logsPage++;
        fetchLogs();
    });

    DOM.closeModalBtn.addEventListener('click', () => {
        DOM.logDetailModal.style.display = 'none';
    });

    window.onclick = function(e) {
        if (e.target === DOM.logDetailModal) {
            DOM.logDetailModal.style.display = 'none';
        }
    };
}

async function fetchLogs() {
    try {
        const offset = STATE.logsPage * STATE.logsLimit;
        let url = `/api/v1/monitoring/logs?limit=${STATE.logsLimit}&offset=${offset}`;
        if (STATE.logsAction) {
            url += `&action=${STATE.logsAction}`;
        }
        
        const res = await fetch(url);
        let logs = await res.json();
        STATE.logs = logs;

        // Apply search locally
        if (STATE.logsSearch) {
            const query = STATE.logsSearch.toLowerCase();
            logs = logs.filter(l => 
                l.user_id.toLowerCase().includes(query) || 
                l.prompt.toLowerCase().includes(query)
            );
        }

        renderLogsTable(logs);
        updatePaginationLabels(logs.length);
    } catch (e) {
        console.error("Failed to fetch logs", e);
    }
}

function renderLogsTable(logs) {
    const tbody = DOM.logsTbody;
    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="table-empty">No transaction records found matching active query.</td></tr>`;
        return;
    }

    let html = '';
    logs.forEach(l => {
        const date = new Date(l.timestamp).toLocaleString();
        const actionBadgeClass = getActionBadgeClass(l.action_taken);
        const scoreClass = l.risk_score > 0.75 ? 'high' : l.risk_score > 0.4 ? 'medium' : 'low';
        
        html += `
            <tr>
                <td>${date}</td>
                <td><code>${escapeHtml(l.user_id)}</code></td>
                <td title="${escapeHtml(l.prompt)}">${escapeHtml(truncateString(l.prompt, 40))}</td>
                <td><span class="badge-risk ${scoreClass}">${l.risk_score.toFixed(2)}</span></td>
                <td>${l.duration.toFixed(3)}s</td>
                <td><span class="badge-status ${actionBadgeClass}">${l.action_taken}</span></td>
                <td><button class="btn-text" onclick="viewLogDetail('${l.id}')">Inspect</button></td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

function updatePaginationLabels(count) {
    const start = STATE.logsPage * STATE.logsLimit + 1;
    const end = start + count - 1;
    
    if (count === 0) {
        DOM.paginationInfoLabel.innerText = "Showing 0 logs";
        DOM.paginationPrev.disabled = true;
        DOM.paginationNext.disabled = true;
    } else {
        DOM.paginationInfoLabel.innerText = `Showing records ${start}-${end}`;
        DOM.paginationPrev.disabled = STATE.logsPage === 0;
        // Disable next if we loaded fewer records than the limit
        DOM.paginationNext.disabled = count < STATE.logsLimit;
    }
}

window.viewLogDetail = function(logId) {
    const log = STATE.logs.find(l => String(l.id) === String(logId));
    if (!log) return;

    DOM.logDetailModal.style.display = 'flex';
    
    const anomaliesList = (log.anomalies || []).map(a => `
        <li style="color: var(--accent-orange); margin-bottom: 5px;">
            <i class="fa-solid fa-triangle-exclamation"></i> <strong>${escapeHtml(a.type || 'Anomaly')}:</strong> ${escapeHtml(a.description || 'Reason missing')}
        </li>
    `).join('');

    DOM.logModalBody.innerHTML = `
        <div class="modal-details-grid">
            <div class="modal-meta-row">
                <div class="meta-box">
                    <span>Sender User</span>
                    <strong><code>${escapeHtml(log.user_id)}</code></strong>
                </div>
                <div class="meta-box">
                    <span>Gateway Action</span>
                    <strong>${log.action_taken}</strong>
                </div>
                <div class="meta-box">
                    <span>Latency Duration</span>
                    <strong>${log.duration.toFixed(3)}s</strong>
                </div>
            </div>
            
            <div class="modal-row-item">
                <span>Prompt Input Text</span>
                <blockquote>${escapeHtml(log.prompt)}</blockquote>
            </div>

            <div class="modal-row-item">
                <span>Response Output Content</span>
                <blockquote>${escapeHtml(log.response || '(Empty or Blocked)')}</blockquote>
            </div>

            ${anomaliesList ? `
                <div class="modal-row-item">
                    <span>Flagged Anomalies</span>
                    <ul style="list-style: none; padding-left: 0;">${anomaliesList}</ul>
                </div>
            ` : ''}
            
            <div class="modal-meta-row" style="margin-top: 10px;">
                <div class="meta-box">
                    <span>Risk Classification</span>
                    <strong>${log.risk_score.toFixed(3)}</strong>
                </div>
                <div class="meta-box">
                    <span>Policy Flagged</span>
                    <strong>${log.flagged ? 'Yes' : 'No'}</strong>
                </div>
                <div class="meta-box">
                    <span>Client System IP</span>
                    <strong><code>${escapeHtml(log.client_ip || '127.0.0.1')}</code></strong>
                </div>
            </div>
        </div>
    `;
};

// -----------------------------------------------------
// 5. RED-TEAMING ATTACK SIMULATIONS
// -----------------------------------------------------
function initRedTeaming() {
    DOM.runRedteamScanBtn.addEventListener('click', executeRedteamScan);
}

async function fetchRedteamPayloads() {
    try {
        const res = await fetch('/api/v1/redteaming/payloads');
        STATE.redteamPayloads = await res.json();
        
        let html = '';
        STATE.redteamPayloads.forEach(p => {
            html += `
                <div class="payload-row">
                    <span class="payload-category">${escapeHtml(p.category)}</span>
                    <div class="payload-desc">
                        <h5>${escapeHtml(p.description)}</h5>
                        <p>${escapeHtml(p.prompt)}</p>
                    </div>
                </div>
            `;
        });
        
        DOM.payloadsRegistryList.innerHTML = html;
    } catch (e) {
        console.error("Failed to load redteam payloads", e);
    }
}

async function executeRedteamScan() {
    if (STATE.isScanning) return;
    
    STATE.isScanning = true;
    DOM.runRedteamScanBtn.disabled = true;
    DOM.scanProgressArea.style.display = 'block';
    DOM.scanReportContainer.style.display = 'none';
    
    // Simulate step progress increments first for awesome UI visual impact
    let percent = 0;
    const progressInterval = setInterval(() => {
        if (percent < 90) {
            percent += Math.floor(Math.random() * 8) + 4;
            percent = Math.min(percent, 90);
            DOM.scanProgressFill.style.width = `${percent}%`;
            DOM.scanProgressPercent.innerText = `${percent}%`;
            DOM.scanProgressStatus.innerText = getScanStatusLabel(percent);
        }
    }, 180);

    try {
        const res = await fetch('/api/v1/redteaming/scan', { method: 'POST' });
        const report = await res.json();
        
        clearInterval(progressInterval);
        
        // Set final 100%
        DOM.scanProgressFill.style.width = `100%`;
        DOM.scanProgressPercent.innerText = `100%`;
        DOM.scanProgressStatus.innerText = "Scan report compiled!";
        
        setTimeout(() => {
            DOM.scanProgressArea.style.display = 'none';
            DOM.runRedteamScanBtn.disabled = false;
            STATE.isScanning = false;
            
            renderRedteamReport(report);
            
            // Sync overview cards
            fetchStats();
        }, 800);

    } catch (e) {
        clearInterval(progressInterval);
        DOM.scanProgressArea.style.display = 'none';
        DOM.runRedteamScanBtn.disabled = false;
        STATE.isScanning = false;
        alert(`Redteam audit failure: ${e.message}`);
    }
}

function getScanStatusLabel(percent) {
    if (percent < 25) return "Executing system leakage injections...";
    if (percent < 50) return "Running character roleplay & DAN jailbreaks...";
    if (percent < 75) return "Testing hex/base64 obfuscation filters...";
    return "Testing shell command injection vectors...";
}

function renderRedteamReport(report) {
    DOM.scanReportContainer.style.display = 'block';
    
    const metrics = report.metrics;
    DOM.reportPosture.innerText = metrics.security_posture;
    DOM.reportBlocked.innerText = `${metrics.blocked}/${metrics.malicious_tested}`;
    DOM.reportBypassed.innerText = metrics.bypassed;
    DOM.reportDuration.innerText = `${report.scan_duration_seconds}s`;
    
    // Color status posture
    DOM.reportPosture.className = metrics.security_posture === 'Excellent' ? 'text-success' : 'text-danger';
    
    // Redraw table
    let html = '';
    report.results.forEach(r => {
        const outcomeText = r.bypass ? 'Bypassed' : 'Blocked';
        const outcomeClass = r.bypass ? 'badge-status blocked' : 'badge-status allowed'; // Red for bypass, green for blocked (success!)
        const actionBadgeClass = getActionBadgeClass(r.action_taken || 'allowed');
        
        html += `
            <tr>
                <td><code>${escapeHtml(r.id)}</code></td>
                <td><span style="font-size: 11px; font-weight: 700; color: var(--accent-purple);">${escapeHtml(r.category)}</span></td>
                <td><small>${escapeHtml(r.description)}</small></td>
                <td><strong style="font-size: 13px;">${(r.risk_score || 0.0).toFixed(2)}</strong></td>
                <td><span class="badge-status ${actionBadgeClass}">${r.action_taken || 'allowed'}</span></td>
                <td><span class="${outcomeClass}">${outcomeText}</span></td>
            </tr>
        `;
    });
    
    DOM.redteamReportTbody.innerHTML = html;
}

// -----------------------------------------------------
// 6. INTERACTIVE GATEWAY PLAYGROUND
// -----------------------------------------------------
function initPlayground() {
    DOM.playgroundForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const prompt = DOM.playPrompt.value;
        const systemPrompt = DOM.playSystemPrompt.value;
        const retrievedContext = DOM.playRetrievedContext.value;
        const userId = DOM.playUserId.value;
        const executeCode = DOM.playExecute.checked;
        const context = DOM.playContext.value;
        
        // UI Reset
        DOM.playgroundResultCard.style.display = 'none';
        resetPipelineSteps();
        
        // Start animation pipeline stream
        DOM.playgroundSubmitBtn.disabled = true;
        DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Securing...';
        
        try {
            // Step 1: Direct Sanitizer active
            setStepStatus(DOM.stepSanitize, 'active');
            await sleep(350);
            
            // Make actual API call
            const res = await fetch('/api/v1/process', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    prompt: prompt,
                    system_prompt: systemPrompt,
                    retrieved_context: retrievedContext,
                    user_id: userId,
                    context: context,
                    model: 'gpt-3.5-turbo',
                    execute_code: executeCode
                })
            });
            const data = await res.json();
            
            // Step 1 check
            const isBlockedAtInput = data.action_taken === 'blocked_input';
            setStepStatus(DOM.stepSanitize, isBlockedAtInput ? 'blocked' : 'success');
            
            if (isBlockedAtInput) {
                DOM.playgroundSubmitBtn.disabled = false;
                DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
                renderPlaygroundResult(data);
                return;
            }

            // Step 2: RAG context check
            setStepStatus(DOM.stepContext, 'active');
            await sleep(350);
            const isBlockedAtContext = data.action_taken === 'blocked_indirect_injection';
            setStepStatus(DOM.stepContext, isBlockedAtContext ? 'blocked' : 'success');

            if (isBlockedAtContext) {
                DOM.playgroundSubmitBtn.disabled = false;
                DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
                renderPlaygroundResult(data);
                return;
            }

            // Step 3: Classifier active
            setStepStatus(DOM.stepClassify, 'active');
            await sleep(350);
            setStepStatus(DOM.stepClassify, data.security_score > 0.4 ? 'blocked' : 'success');
            
            // Step 4: Policies active
            setStepStatus(DOM.stepPolicy, 'active');
            await sleep(300);
            const isBlockedAtHITL = data.action_taken === 'hitl_denied';
            setStepStatus(DOM.stepPolicy, isBlockedAtHITL ? 'blocked' : 'success');
            
            if (isBlockedAtHITL) {
                DOM.playgroundSubmitBtn.disabled = false;
                DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
                renderPlaygroundResult(data);
                return;
            }

            // Step 5: Sandbox execution check
            if (executeCode && data.sandbox_result) {
                DOM.connectorSandbox.classList.add('active');
                DOM.stepSandbox.style.display = 'flex';
                setStepStatus(DOM.stepSandbox, 'active');
                await sleep(350);
                
                const isBlockedSandbox = data.action_taken === 'blocked_sandbox_violation';
                setStepStatus(DOM.stepSandbox, isBlockedSandbox ? 'blocked' : 'success');
                
                if (isBlockedSandbox) {
                    DOM.playgroundSubmitBtn.disabled = false;
                    DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
                    renderPlaygroundResult(data);
                    return;
                }
            } else {
                DOM.connectorSandbox.style.display = 'none';
                DOM.stepSandbox.style.display = 'none';
            }

            // Step 6: Leakage guard check
            setStepStatus(DOM.stepLeakage, 'active');
            await sleep(300);
            const isBlockedLeakage = data.action_taken === 'blocked_system_leak';
            setStepStatus(DOM.stepLeakage, isBlockedLeakage ? 'blocked' : 'success');

            if (isBlockedLeakage) {
                DOM.playgroundSubmitBtn.disabled = false;
                DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
                renderPlaygroundResult(data);
                return;
            }

            // Step 7: Redactor check
            setStepStatus(DOM.stepOutput, 'active');
            await sleep(300);
            const hasRedaction = data.action_taken === 'redacted_output';
            setStepStatus(DOM.stepOutput, hasRedaction ? 'blocked' : 'success');
            
            // Show result block
            DOM.playgroundSubmitBtn.disabled = false;
            DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
            renderPlaygroundResult(data);

        } catch (e) {
            DOM.playgroundSubmitBtn.disabled = false;
            DOM.playgroundSubmitBtn.querySelector('span').innerText = 'Transmit Through Gateway';
            resetPipelineSteps();
            alert(`Gateway communication error: ${e.message}`);
        }
    });
}

function resetPipelineSteps() {
    const steps = [DOM.stepSanitize, DOM.stepContext, DOM.stepClassify, DOM.stepPolicy, DOM.stepSandbox, DOM.stepLeakage, DOM.stepOutput];
    steps.forEach(s => {
        if (s) s.className = 'pipeline-step';
    });
    DOM.connectorSandbox.className = 'pipeline-connector';
    DOM.connectorSandbox.style.display = 'block';
    DOM.stepSandbox.style.display = 'flex';
}

function setStepStatus(stepElement, status) {
    stepElement.className = `pipeline-step ${status}`;
}

function renderPlaygroundResult(data) {
    DOM.playgroundResultCard.style.display = 'flex';
    
    // Action verdict badge
    DOM.playVerdictBadge.innerText = data.action_taken;
    DOM.playVerdictBadge.className = `action-badge ${getVerdictClass(data.action_taken)}`;
    
    // Risk telemetry
    DOM.playRiskScore.innerText = data.security_score.toFixed(3);
    DOM.playDuration.innerText = `${data.processing_time.toFixed(3)}s`;
    
    // Sandbox detail
    if (data.sandbox_result) {
        DOM.playSandboxBlock.style.display = 'block';
        if (data.sandbox_result.success) {
            DOM.playSandboxOutput.style.color = 'var(--accent-green)';
            DOM.playSandboxOutput.innerText = data.sandbox_result.output || '(No script outputs returned)';
        } else {
            DOM.playSandboxOutput.style.color = 'var(--accent-red)';
            DOM.playSandboxOutput.innerText = data.sandbox_result.error || 'Execution blocked by gateway';
        }
    } else {
        DOM.playSandboxBlock.style.display = 'none';
    }

    // Output redactions highlighting
    let formattedResponse = escapeHtml(data.response);
    // Visual highlighters for redactions
    formattedResponse = formattedResponse.replaceAll(
        '[REDACTED CREDIT CARD]', '<span style="color: var(--accent-orange); font-weight:700;">[REDACTED CREDIT CARD]</span>'
    ).replaceAll(
        '[REDACTED EMAIL]', '<span style="color: var(--accent-orange); font-weight:700;">[REDACTED EMAIL]</span>'
    ).replaceAll(
        '[REDACTED PHONE]', '<span style="color: var(--accent-orange); font-weight:700;">[REDACTED PHONE]</span>'
    ).replaceAll(
        '[REDACTED OPENAI KEY]', '<span style="color: var(--accent-red); font-weight:700;">[REDACTED OPENAI KEY]</span>'
    ).replaceAll(
        '/* [REDACTED CREDENTIAL] */', '<span style="color: var(--accent-red); font-weight:700;">/* [REDACTED CREDENTIAL] */</span>'
    );

    DOM.playResponseText.innerHTML = formattedResponse;

    // Anomalies
    if (data.anomalies && data.anomalies.length > 0) {
        DOM.playAnomaliesBlock.style.display = 'block';
        DOM.playAnomaliesList.innerHTML = data.anomalies.map(a => `
            <li><strong>${escapeHtml(a.type)}:</strong> ${escapeHtml(a.description)}</li>
        `).join('');
    } else {
        DOM.playAnomaliesBlock.style.display = 'none';
    }
}

function getVerdictClass(action) {
    if (action === 'allowed') return 'allowed';
    if (action.startsWith('blocked') || action === 'hitl_denied') return 'blocked';
    return 'pending';
}

// -----------------------------------------------------
// UTILITY HELPERS
// -----------------------------------------------------
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function truncateString(str, len) {
    if (str.length <= len) return str;
    return str.substring(0, len) + '...';
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getActionBadgeClass(action) {
    if (action === 'allowed') return 'allowed';
    if (action.startsWith('blocked') || action === 'hitl_denied') return 'blocked';
    if (action === 'hitl_pending') return 'pending';
    if (action === 'redacted_output') return 'redacted';
    return 'pending';
}
