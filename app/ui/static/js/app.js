/**
 * CYBERTRACE - Frontend Dashboard Controller
 * Vanilla JavaScript implementation providing interactive SOC capabilities,
 * instant 1-click sample analysis, incident drill-down, and report access.
 */

// Global Application State
const state = {
    currentRunId: null,
    currentRunMeta: null,
    activeTab: 'dashboard',
    cachedIncidents: [],
    eventsFilter: {
        severity: '',
        eventType: '',
        search: ''
    },
    incidentsFilter: {
        severity: '',
        search: ''
    },
    timelineState: {
        incidents: [],
        activeIncidentId: null,
        activeIncidentDetail: null,
        activeFilter: 'ALL',
        selectedEventIndex: 0
    },
    modalState: {
        incident: null,
        selectedEventIndex: 0
    }
};

// Initialization on DOM Content Loaded
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUploadHandlers();
    loadSamplesList();
    loadInitialState();
    checkSystemHealth();
});

// ================= Navigation & Routing =================
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = link.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    state.activeTab = tabId;
    
    // Update navigation menu active states
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.getAttribute('data-tab') === tabId);
    });

    // Update view visibility
    document.querySelectorAll('.page-view').forEach(view => {
        view.classList.toggle('active', view.id === `view-${tabId}`);
    });

    // Refresh view content
    if (tabId === 'dashboard') loadDashboard();
    if (tabId === 'events') loadEvents();
    if (tabId === 'incidents') loadIncidents();
    if (tabId === 'iocs') loadIOCs();
    if (tabId === 'timeline') loadTimeline();
    if (tabId === 'reports') loadReportsView();
}

// ================= System Health Check =================
async function checkSystemHealth() {
    try {
        const res = await fetch('/api/health');
        if (!res.ok) throw new Error('Health check non-200');
        const data = await res.json();
        const backendBadge = document.getElementById('health-backend-badge');
        const dbBadge = document.getElementById('health-db-badge');

        if (backendBadge) {
            if (data.status === 'healthy') {
                backendBadge.className = 'health-pill online';
                backendBadge.innerHTML = '<span class="status-dot"></span> Backend: ONLINE';
            } else {
                backendBadge.className = 'health-pill degraded';
                backendBadge.innerHTML = '<span class="status-dot"></span> Backend: DEGRADED';
            }
        }

        if (dbBadge) {
            if (data.database === 'healthy') {
                dbBadge.className = 'health-pill online';
                dbBadge.innerHTML = '<span class="status-dot"></span> SQLite: ONLINE';
            } else {
                dbBadge.className = 'health-pill degraded';
                dbBadge.innerHTML = '<span class="status-dot"></span> SQLite: DEGRADED';
            }
        }
    } catch (err) {
        const backendBadge = document.getElementById('health-backend-badge');
        const dbBadge = document.getElementById('health-db-badge');
        if (backendBadge) {
            backendBadge.className = 'health-pill offline';
            backendBadge.innerHTML = '<span class="status-dot"></span> Backend: OFFLINE';
        }
        if (dbBadge) {
            dbBadge.className = 'health-pill offline';
            dbBadge.innerHTML = '<span class="status-dot"></span> SQLite: OFFLINE';
        }
    }
}

// ================= Initial State Loader =================
async function loadInitialState() {
    try {
        await checkSystemHealth();
        const res = await fetch('/api/runs');
        const runs = await res.json();
        if (runs && runs.length > 0) {
            state.currentRunId = runs[0].id;
            state.currentRunMeta = runs[0];
            updateTopBar(runs[0]);
        }
        await loadDashboard();
    } catch (err) {
        console.error('Error initializing state:', err);
        showToast('Connected to CyberTrace server.', 'info');
    }
}

function updateTopBar(run) {
    const targetLabel = document.getElementById('active-run-target');
    if (targetLabel) {
        if (!run) {
            targetLabel.textContent = 'None';
            return;
        }
        const rId = run.id || run.run_id || '';
        targetLabel.textContent = rId ? `${run.filename} (Run #${rId})` : `${run.filename}`;
    }
}

// ================= Toast Notifications =================
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'error') toast.style.borderLeftColor = 'var(--sev-critical)';
    if (type === 'success') toast.style.borderLeftColor = 'var(--sev-low)';
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// ================= 1. Dashboard View =================
async function loadDashboard() {
    try {
        const statsUrl = state.currentRunId ? `/api/statistics?run_id=${state.currentRunId}` : '/api/statistics';
        const res = await fetch(statsUrl);
        const stats = await res.json();

        document.getElementById('stat-total-events').textContent = stats.total_events || 0;
        document.getElementById('stat-suspicious-events').textContent = stats.suspicious_events || 0;
        document.getElementById('stat-total-incidents').textContent = stats.total_incidents || 0;
        document.getElementById('stat-critical-incidents').textContent = stats.critical_incidents || 0;
        document.getElementById('stat-unique-ips').textContent = stats.unique_ips || 0;
        document.getElementById('stat-observed-iocs').textContent = stats.total_iocs || 0;

        let incidents = [];
        let events = [];
        if (state.currentRunId) {
            const incRes = await fetch(`/api/incidents?run_id=${state.currentRunId}`);
            incidents = await incRes.json();
            const evRes = await fetch(`/api/events?run_id=${state.currentRunId}&limit=100`);
            const evData = await evRes.json();
            events = evData.events || [];
            renderDashboardIncidents(incidents);
        } else {
            renderDashboardIncidents([]);
        }

        renderVisualAnalytics(stats, events, incidents);
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

function renderVisualAnalytics(stats, events, incidents) {
    renderSeverityDonut(incidents);
    renderEventTypeBars(stats, events);
}

function renderSeverityDonut(incidents) {
    const container = document.getElementById('chart-severity-container');
    const summaryLabel = document.getElementById('chart-sev-summary');
    if (!container) return;

    const total = incidents ? incidents.length : 0;
    if (summaryLabel) {
        summaryLabel.textContent = `${total} Active Incident${total === 1 ? '' : 's'}`;
    }

    if (total === 0) {
        container.innerHTML = `
            <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:18px;">
                <svg width="56" height="56" viewBox="0 0 56 56" fill="none" style="margin-bottom:8px;">
                    <circle cx="28" cy="28" r="24" stroke="rgba(16, 185, 129, 0.3)" stroke-width="3" stroke-dasharray="4 4" />
                    <path d="M19 28L25 34L37 22" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <div style="font-size:13px; font-weight:600; color:#34d399;">Clean Baseline</div>
                <div style="font-size:11.5px; color:var(--text-dim); margin-top:2px;">No active incident alerts detected</div>
            </div>
        `;
        return;
    }

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    incidents.forEach(inc => {
        const lvl = (inc.risk_level || 'LOW').toUpperCase();
        if (counts[lvl] !== undefined) counts[lvl]++;
        else counts[lvl] = 1;
    });

    const colors = {
        CRITICAL: '#ef4444',
        HIGH: '#f97316',
        MEDIUM: '#fbbf24',
        LOW: '#10b981'
    };

    const radius = 38;
    const circ = 2 * Math.PI * radius;
    let accumulatedOffset = 0;
    const segments = [];

    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(key => {
        const count = counts[key] || 0;
        if (count > 0) {
            const fraction = count / total;
            const strokeDasharray = `${fraction * circ} ${circ}`;
            const strokeDashoffset = -accumulatedOffset;
            accumulatedOffset += fraction * circ;
            segments.push(`
                <circle cx="60" cy="60" r="${radius}" fill="none"
                    stroke="${colors[key]}" stroke-width="14"
                    stroke-dasharray="${strokeDasharray}"
                    stroke-dashoffset="${strokeDashoffset}"
                    transform="rotate(-90 60 60)" />
            `);
        }
    });

    const legendItems = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(key => {
        const count = counts[key] || 0;
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        return `
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; font-size:12px; margin-bottom:5px;">
                <div style="display:flex; align-items:center; gap:6px;">
                    <span style="width:8px; height:8px; border-radius:50%; background:${colors[key]}; display:inline-block;"></span>
                    <span style="color:var(--text-muted); font-weight:500;">${key}</span>
                </div>
                <div style="font-weight:600; color:var(--text-main);">
                    ${count} <span style="font-size:11px; color:var(--text-dim); font-weight:normal;">(${pct}%)</span>
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-around; width:100%; gap:16px;">
            <div style="position:relative; width:120px; height:120px; flex-shrink:0;">
                <svg width="120" height="120" viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="${radius}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="14" />
                    ${segments.join('')}
                </svg>
                <div style="position:absolute; top:0; left:0; width:100%; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center; pointer-events:none;">
                    <span style="font-size:22px; font-weight:800; color:#fff; line-height:1;">${total}</span>
                    <span style="font-size:9.5px; text-transform:uppercase; color:var(--text-dim); letter-spacing:0.5px; margin-top:2px;">TOTAL</span>
                </div>
            </div>
            <div style="flex:1; max-width:200px;">
                ${legendItems}
            </div>
        </div>
    `;
}

function renderEventTypeBars(stats, events) {
    const container = document.getElementById('chart-events-container');
    const summaryLabel = document.getElementById('chart-events-summary');
    if (!container) return;

    if (!events || events.length === 0) {
        if (summaryLabel) summaryLabel.textContent = '0 Ingested Events';
        container.innerHTML = `
            <div class="chart-empty-state">No event telemetry loaded</div>
        `;
        return;
    }

    if (summaryLabel) {
        summaryLabel.textContent = `${stats.total_events || events.length} Ingested Events`;
    }

    const counts = {};
    events.forEach(e => {
        const t = e.event_type || 'OTHER';
        counts[t] = (counts[t] || 0) + 1;
    });

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const maxVal = Math.max(...sorted.map(s => s[1]), 1);

    const barsHtml = sorted.map(([type, count]) => {
        const pct = Math.round((count / maxVal) * 100);
        return `
            <div style="margin-bottom:8px;">
                <div style="display:flex; justify-content:space-between; align-items:center; font-size:11.5px; margin-bottom:3px;">
                    <span style="font-family:monospace; color:var(--accent-cyan); font-weight:500;">${escapeHtml(type)}</span>
                    <span style="color:var(--text-main); font-weight:600;">${count}</span>
                </div>
                <div style="height:6px; background:rgba(255,255,255,0.06); border-radius:3px; overflow:hidden;">
                    <div style="width:${pct}%; height:100%; background:linear-gradient(90deg, #0284c7, #38bdf8); border-radius:3px; transition:width 0.3s ease;"></div>
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = `
        <div style="width:100%; padding:0 8px;">
            ${barsHtml}
        </div>
    `;
}

function renderDashboardIncidents(incidents) {
    const container = document.getElementById('dashboard-incidents-list');
    if (!container) return;

    if (!incidents || incidents.length === 0) {
        container.innerHTML = `
            <div style="padding: 24px; text-align: center; color: var(--text-muted);">
                <p>No incidents detected yet. Ingest a log file or select a sample from the Upload tab.</p>
            </div>
        `;
        return;
    }

    let html = '';
    incidents.slice(0, 3).forEach(inc => {
        const sevClass = inc.risk_level.toLowerCase();
        html += `
            <div style="background:var(--bg-card-header); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span class="badge badge-tag">${inc.incident_code}</span>
                    <strong style="margin-left:8px; font-size:14px;">${escapeHtml(inc.title)}</strong>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                        Source IP: <code>${inc.source_ip || 'N/A'}</code> &bull; User: <code>${inc.username || 'N/A'}</code> &bull; Events: ${inc.event_count}
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:12px;">
                    <span class="badge badge-${sevClass}">${inc.risk_level} (${inc.risk_score}/100)</span>
                    <button class="btn btn-secondary btn-sm" onclick="openIncidentModal(${inc.id})">Investigate</button>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

// ================= 2. Log Upload & Samples =================
function initUploadHandlers() {
    const dropzone = document.getElementById('log-dropzone');
    const fileInput = document.getElementById('file-input');

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleFileUpload(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleFileUpload(fileInput.files[0]);
            }
        });
    }
}

async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    showToast(`Ingesting ${file.name}...`, 'info');
    try {
        const res = await fetch('/api/logs/upload', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Upload failed');
        }

        showToast(data.message, 'success');
        state.currentRunId = data.run_id;
        state.currentRunMeta = data;
        updateTopBar(data);
        switchTab('dashboard');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function loadSamplesList() {
    try {
        const res = await fetch('/api/samples');
        const samples = await res.json();
        const container = document.getElementById('samples-container');
        if (!container) return;

        let html = '';
        samples.forEach(s => {
            html += `
                <div class="sample-card">
                    <div>
                        <h4>${s.name}</h4>
                        <p>${s.description}</p>
                    </div>
                    <div>
                        <button class="btn btn-primary btn-sm" onclick="runSampleAnalysis('${s.name}')">
                            Analyze Sample
                        </button>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    } catch (err) {
        console.error('Error loading sample list:', err);
    }
}

async function runSampleAnalysis(sampleName) {
    showToast(`Analyzing ${sampleName}...`, 'info');
    try {
        const res = await fetch(`/api/samples/analyze/${encodeURIComponent(sampleName)}`, {
            method: 'POST'
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Analysis error');
        }

        showToast(data.message, 'success');
        state.currentRunId = data.run_id;
        state.currentRunMeta = data;
        updateTopBar(data);
        switchTab('dashboard');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// ================= 3. Events View =================
async function loadEvents() {
    if (!state.currentRunId) {
        document.getElementById('events-tbody').innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px;">No log run active.</td></tr>';
        return;
    }

    const { severity, eventType, search } = state.eventsFilter;
    let url = `/api/events?run_id=${state.currentRunId}&limit=100`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    if (eventType) url += `&event_type=${encodeURIComponent(eventType)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById('events-tbody');
        document.getElementById('events-count-label').textContent = `Showing ${data.events.length} of ${data.total} events`;

        if (!data.events || data.events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No matching events found.</td></tr>';
            return;
        }

        let html = '';
        data.events.forEach(ev => {
            const sevClass = (ev.severity || 'LOW').toLowerCase();
            html += `
                <tr>
                    <td><code>${ev.timestamp || 'N/A'}</code></td>
                    <td><span class="badge badge-tag">${ev.event_type}</span></td>
                    <td><span class="badge badge-${sevClass}">${ev.severity}</span></td>
                    <td><code>${ev.source_ip || '-'}</code></td>
                    <td><code>${ev.username || '-'}</code></td>
                    <td>${escapeHtml(ev.message)}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        console.error('Error loading events:', err);
    }
}

function applyEventsFilter() {
    state.eventsFilter.search = document.getElementById('event-search-input').value.trim();
    state.eventsFilter.severity = document.getElementById('event-severity-select').value;
    state.eventsFilter.eventType = document.getElementById('event-type-select').value;
    loadEvents();
}

// ================= 4. Incidents View =================
async function loadIncidents() {
    if (!state.currentRunId) {
        document.getElementById('incidents-container').innerHTML = '<p style="padding:20px; color:var(--text-muted);">No analysis run selected.</p>';
        return;
    }

    try {
        const res = await fetch(`/api/incidents?run_id=${state.currentRunId}`);
        const incidents = await res.json();
        state.cachedIncidents = incidents || [];
        applyIncidentsFilter();
    } catch (err) {
        console.error('Error loading incidents:', err);
    }
}

function applyIncidentsFilter() {
    const searchInput = document.getElementById('incident-search-input');
    const sevSelect = document.getElementById('incident-severity-select');
    const search = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const severity = sevSelect ? sevSelect.value.toUpperCase() : '';

    const all = state.cachedIncidents || [];
    let filtered = all.filter(inc => {
        if (severity && (inc.risk_level || '').toUpperCase() !== severity) return false;
        if (search) {
            const combined = `${inc.incident_code || ''} ${inc.title || ''} ${inc.source_ip || ''} ${inc.username || ''} ${inc.attack_pattern || ''}`.toLowerCase();
            if (!combined.includes(search)) return false;
        }
        return true;
    });

    const countLabel = document.getElementById('incidents-count-label');
    if (countLabel) {
        countLabel.textContent = `Showing ${filtered.length} of ${all.length} incidents`;
    }

    renderIncidentsList(filtered, all.length);
}

function renderIncidentsList(incidents, totalAvailable) {
    const container = document.getElementById('incidents-container');
    if (!container) return;

    if (totalAvailable === 0) {
        container.innerHTML = `
            <div class="card" style="padding:30px; text-align:center; color:var(--text-muted);">
                <h3>No Security Incidents Detected</h3>
                <p>The events in this log run did not trigger any correlated attack chains or rule thresholds.</p>
            </div>
        `;
        return;
    }

    if (!incidents || incidents.length === 0) {
        container.innerHTML = `
            <div class="card" style="padding:24px; text-align:center; color:var(--text-muted);">
                <p>No incidents match the selected filter criteria.</p>
            </div>
        `;
        return;
    }

    let html = '';
    incidents.forEach(inc => {
        const sevClass = inc.risk_level.toLowerCase();
        const rulesTags = (inc.rules_triggered || []).map(r => `<span class="badge badge-tag">${r}</span>`).join(' ');

        html += `
            <div class="card" style="margin-bottom:20px;">
                <div class="card-header">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span class="badge badge-tag" style="font-size:12px;">${inc.incident_code}</span>
                        <span class="card-title">${escapeHtml(inc.title)}</span>
                    </div>
                    <span class="badge badge-${sevClass}">${inc.risk_level} (${inc.risk_score}/100)</span>
                </div>
                <div class="card-body">
                    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:10px; font-size:13px; margin-bottom:14px; background:var(--bg-sidebar); padding:12px; border-radius:6px;">
                        <div><strong>Source IP:</strong> <code>${inc.source_ip || 'N/A'}</code></div>
                        <div><strong>Username:</strong> <code>${inc.username || 'N/A'}</code></div>
                        <div><strong>First Observed:</strong> <code>${inc.first_observed || 'N/A'}</code></div>
                        <div><strong>Last Observed:</strong> <code>${inc.last_observed || 'N/A'}</code></div>
                    </div>

                    <div style="margin-bottom:14px;">
                        <strong style="font-size:13px;">Attack Pattern Progression:</strong>
                        <div class="attack-chain-banner">
                            ${escapeHtml(inc.attack_pattern)}
                        </div>
                    </div>

                    <div style="margin-bottom:16px;">
                        <strong style="font-size:13px;">Triggered Rules:</strong><br/>
                        <div style="margin-top:6px;">${rulesTags || '<em>None</em>'}</div>
                    </div>

                    <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid var(--border-color); padding-top:14px;">
                        <span style="font-size:12px; color:var(--text-muted);">${inc.event_count} correlated security events</span>
                        <button class="btn btn-primary" onclick="openIncidentModal(${inc.id})">Investigate Incident Details</button>
                    </div>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

// ================= Helper Functions for Forensic Telemetry =================
function getIpClassification(ip) {
    if (!ip || ip === '-' || ip === 'N/A') return null;
    const cleanIp = String(ip).trim();
    if (cleanIp.startsWith('127.') || cleanIp === '::1' || cleanIp.toLowerCase() === 'localhost') {
        return { type: 'Loopback', isPrivate: true, badge: '<span class="badge badge-low" style="font-size:10px; margin-left:6px;">Loopback</span>' };
    }
    if (cleanIp.startsWith('10.') || cleanIp.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp)) {
        return { type: 'Private RFC1918', isPrivate: true, badge: '<span class="badge badge-low" style="font-size:10px; margin-left:6px;">Internal Private</span>' };
    }
    return { type: 'Public / External', isPrivate: false, badge: '<span class="badge badge-critical" style="font-size:10px; margin-left:6px;">External Public</span>' };
}

function getEventClassification(ev) {
    const sev = (ev.severity || 'LOW').toUpperCase();
    const rules = (ev.extra_data && ev.extra_data.matched_rules) ? ev.extra_data.matched_rules : [];

    if (rules.length > 0 || sev === 'CRITICAL') {
        return {
            category: 'Incident Trigger',
            badgeClass: 'badge-critical',
            isTrigger: true,
            isSuspicious: true
        };
    }
    if (sev === 'HIGH') {
        return {
            category: 'Suspicious Escalation',
            badgeClass: 'badge-high',
            isTrigger: false,
            isSuspicious: true
        };
    }
    if (sev === 'MEDIUM') {
        return {
            category: 'Anomalous Activity',
            badgeClass: 'badge-medium',
            isTrigger: false,
            isSuspicious: true
        };
    }
    return {
        category: 'Normal Baseline',
        badgeClass: 'badge-low',
        isTrigger: false,
        isSuspicious: false
    };
}

function generateForensicAssessment(ev) {
    const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
    const evType = ev.event_type || '';
    const sev = (ev.severity || 'LOW').toUpperCase();

    if (rules.includes('RULE_001_BRUTE_FORCE')) {
        return 'Deterministic rule <code>RULE_001_BRUTE_FORCE</code> triggered. Rapid sequential authentication failures detected from identical source entity exceeding brute-force thresholds.';
    }
    if (rules.includes('RULE_002_LOGIN_AFTER_FAILURES')) {
        return 'Deterministic rule <code>RULE_002_LOGIN_AFTER_FAILURES</code> triggered. Successful authentication authenticated immediately following repeated failed attempts, indicating credential guessing success.';
    }
    if (rules.includes('RULE_003_ACCOUNT_LOCKOUT')) {
        return 'Deterministic rule <code>RULE_003_ACCOUNT_LOCKOUT</code> triggered. Account locked out after repeated authentication failures.';
    }
    if (rules.includes('RULE_004_PRIVILEGE_ESCALATION')) {
        return 'Deterministic rule <code>RULE_004_PRIVILEGE_ESCALATION</code> triggered. High-risk administrative elevation (sudo/root) executed by target user session.';
    }
    if (rules.includes('RULE_005_SUSPICIOUS_EXTERNAL_CONN')) {
        return 'Deterministic rule <code>RULE_005_SUSPICIOUS_EXTERNAL_CONN</code> triggered. Outbound network telemetry detected connecting to an unverified external public IP address.';
    }

    if (evType === 'LOGIN_FAILED') {
        return 'Authentication failure logged. Monitored for recurrence as part of credential stuffing / brute-force threshold detection.';
    }
    if (evType === 'LOGIN_SUCCESS') {
        return 'Authorized session established. Correlated with preceding failure telemetry to detect unauthorized access.';
    }
    if (evType === 'NETWORK_CONNECTION') {
        return 'Network socket connection event captured. Evaluated against RFC1918 address space and suspicious domain indicators.';
    }
    if (evType === 'PROCESS_EXECUTED' || evType === 'PRIVILEGE_ESCALATION') {
        return 'Endpoint command execution recorded. Monitored for root privileges, credential dumping, or abnormal child processes.';
    }
    if (sev === 'HIGH' || sev === 'CRITICAL') {
        return 'High-severity telemetry flagged for forensic investigation due to elevated threat risk profile.';
    }
    return 'Normal operational baseline event captured within log ingestion window.';
}

function generateAnalystRecommendation(ev) {
    const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
    const ipClass = getIpClassification(ev.source_ip);

    if (rules.includes('RULE_004_PRIVILEGE_ESCALATION')) {
        return 'Verify administrative authorization for user session. If unauthorized, revoke sudo rights and isolate endpoint immediately.';
    }
    if (rules.includes('RULE_005_SUSPICIOUS_EXTERNAL_CONN') || (ipClass && !ipClass.isPrivate)) {
        return 'Block external destination IP on perimeter firewall and inspect active socket connections on affected host.';
    }
    if (rules.includes('RULE_002_LOGIN_AFTER_FAILURES') || rules.includes('RULE_001_BRUTE_FORCE')) {
        return 'Initiate credential reset for affected account. Invalidate active session tokens and enforce multi-factor authentication (MFA).';
    }
    if (rules.includes('RULE_003_ACCOUNT_LOCKOUT')) {
        return 'Maintain account lockout. Contact legitimate account owner to verify whether activity was user-initiated.';
    }
    return 'Maintain baseline logging retention and correlate with adjacent network telemetry.';
}

function copyRawLogPayload(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Raw evidence log copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy to clipboard', 'error');
    });
}

// ================= 5. Incident Details Modal =================
async function openIncidentModal(incidentId) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        const inc = await res.json();
        if (!res.ok) throw new Error(inc.detail || 'Incident not found');

        state.modalState = {
            incident: inc,
            selectedEventIndex: 0
        };

        document.getElementById('modal-incident-title').textContent = `${inc.incident_code}: ${inc.title}`;
        
        const sevClass = inc.risk_level.toLowerCase();
        let factorsHtml = (inc.contributing_factors || []).map(f => `<li><code>${escapeHtml(f)}</code></li>`).join('');
        let recsHtml = (inc.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
        let rulesHtml = (inc.rules_triggered || []).map(r => `<span class="badge badge-tag">${escapeHtml(r)}</span>`).join(' ');

        // Timeline table rows
        const timelineList = inc.timeline || [];
        let timelineRows = '';
        timelineList.forEach((ev, idx) => {
            const isSelected = idx === 0;
            const cls = getEventClassification(ev);
            const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
            const ruleBadges = rules.map(r => `<span class="badge badge-tag" style="font-size:10px;">${escapeHtml(r)}</span>`).join(' ');

            timelineRows += `
                <tr class="selectable-row ${isSelected ? 'selected-row' : ''}" id="modal-row-${idx}" onclick="selectModalTimelineRow(${idx})">
                    <td style="white-space:nowrap; width:35px; text-align:center;"><span class="timeline-step-badge">#${idx + 1}</span></td>
                    <td style="white-space:nowrap;"><code style="white-space:nowrap;">${escapeHtml(ev.timestamp || 'N/A')}</code></td>
                    <td style="white-space:nowrap;"><span class="badge badge-tag">${escapeHtml(ev.event_type)}</span></td>
                    <td style="white-space:nowrap;"><span class="badge ${cls.badgeClass}">${cls.category}</span></td>
                    <td style="white-space:nowrap;"><code>${escapeHtml(ev.source_ip || '-')}</code></td>
                    <td style="white-space:nowrap;"><code>${escapeHtml(ev.username || '-')}</code></td>
                    <td style="word-break:break-word;">
                        ${escapeHtml(ev.message)}
                        ${ruleBadges ? `<div style="margin-top:4px;">${ruleBadges}</div>` : ''}
                    </td>
                </tr>
            `;
        });

        const modalContent = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <div>
                    <span class="badge badge-tag">${escapeHtml(inc.incident_type)}</span>
                    <span style="margin-left:10px; font-size:13px; color:var(--text-muted);">Observed: ${escapeHtml(inc.first_observed || 'N/A')} to ${escapeHtml(inc.last_observed || 'N/A')}</span>
                </div>
                <span class="badge badge-${sevClass}" style="font-size:13px; padding:6px 14px;">Risk: ${escapeHtml(inc.risk_level)} (${inc.risk_score}/100)</span>
            </div>

            <div style="background:var(--bg-sidebar); padding:14px; border-radius:8px; border:1px solid var(--border-color); margin-bottom:18px;">
                <h4 style="font-size:13px; margin-bottom:6px; color:var(--accent-blue);">Attack Pattern Sequence:</h4>
                <div style="font-family:monospace; color:var(--accent-cyan); font-size:13px;">${escapeHtml(inc.attack_pattern)}</div>
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:18px;">
                <div style="background:var(--bg-sidebar); padding:14px; border-radius:8px; border:1px solid var(--border-color);">
                    <h4 style="font-size:13px; margin-bottom:8px; color:#fbbf24;">Risk Scoring Breakdown:</h4>
                    <ul style="padding-left:18px; font-size:12.5px; color:#f8fafc; line-height:1.6;">
                        ${factorsHtml || '<li>Standard baseline event</li>'}
                    </ul>
                </div>
                <div style="background:var(--bg-sidebar); padding:14px; border-radius:8px; border:1px solid var(--border-color);">
                    <h4 style="font-size:13px; margin-bottom:8px; color:var(--accent-cyan);">Recommended SOC Actions:</h4>
                    <ul style="padding-left:18px; font-size:12.5px; color:#f8fafc; line-height:1.6;">
                        ${recsHtml}
                    </ul>
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <h4 style="font-size:13px; margin-bottom:6px;">Detection Rules Triggered:</h4>
                <div>${rulesHtml || '<em>None</em>'}</div>
            </div>

            <div style="margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <h4 style="font-size:13px; margin:0;">Chronological Incident Timeline (${timelineList.length} events):</h4>
                    <span style="font-size:11.5px; color:var(--text-dim);">&#128073; Click any row to inspect raw forensic evidence</span>
                </div>
                <div class="table-wrapper">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th style="width:35px; text-align:center;">#</th>
                                <th style="white-space:nowrap; width:150px;">Timestamp</th>
                                <th style="white-space:nowrap; width:140px;">Event Type</th>
                                <th style="white-space:nowrap; width:120px;">Classification</th>
                                <th style="white-space:nowrap; width:120px;">Source IP</th>
                                <th style="white-space:nowrap; width:90px;">User</th>
                                <th>Evidence Summary</th>
                            </tr>
                        </thead>
                        <tbody>${timelineRows || '<tr><td colspan="7">No timeline events available.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>

            <div id="modal-evidence-inspector-container">
                <!-- Rendered by renderModalEvidenceInspector -->
            </div>
        `;

        document.getElementById('modal-incident-body').innerHTML = modalContent;
        if (timelineList.length > 0) {
            renderModalEvidenceInspector(timelineList[0], 0);
        }
        document.getElementById('incident-modal').classList.add('active');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function selectModalTimelineRow(idx) {
    const inc = state.modalState ? state.modalState.incident : null;
    if (!inc || !inc.timeline || !inc.timeline[idx]) return;

    state.modalState.selectedEventIndex = idx;

    // Update row highlight
    document.querySelectorAll('#modal-incident-body .selectable-row').forEach(row => {
        row.classList.remove('selected-row');
    });
    const targetRow = document.getElementById(`modal-row-${idx}`);
    if (targetRow) targetRow.classList.add('selected-row');

    renderModalEvidenceInspector(inc.timeline[idx], idx);
}

function renderModalEvidenceInspector(ev, idx) {
    const container = document.getElementById('modal-evidence-inspector-container');
    if (!container) return;
    if (!ev) {
        container.innerHTML = '';
        return;
    }

    const inc = state.modalState ? state.modalState.incident : null;
    const total = inc && inc.timeline ? inc.timeline.length : 1;
    const cls = getEventClassification(ev);
    const ipClass = getIpClassification(ev.source_ip);
    const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
    const rulesHtml = rules.map(r => `<span class="badge badge-tag">${escapeHtml(r)}</span>`).join(' ');
    const assessment = generateForensicAssessment(ev);
    const recAction = generateAnalystRecommendation(ev);

    container.innerHTML = `
        <div class="timeline-inspector-card" style="margin-top:16px;">
            <div class="card-header" style="background:var(--bg-card-header); padding:10px 16px; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <strong style="font-size:13px; color:var(--text-main);">&#128269; Selected Event Evidence (Step #${idx + 1} of ${total})</strong>
                </div>
                <span class="badge ${cls.badgeClass}">${cls.category}</span>
            </div>
            <div style="padding:14px;">
                <div class="inspector-meta-grid" style="margin-bottom:12px;">
                    <div>
                        <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Source IP</span>
                        <div style="font-family:monospace; font-size:12px; margin-top:2px;">
                            <code>${escapeHtml(ev.source_ip || 'N/A')}</code>
                            ${ipClass ? ipClass.badge : ''}
                        </div>
                    </div>
                    <div>
                        <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">User / Account</span>
                        <div style="font-family:monospace; font-size:12px; margin-top:2px;">
                            <code>${escapeHtml(ev.username || 'N/A')}</code>
                        </div>
                    </div>
                    <div>
                        <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Event Timestamp</span>
                        <div style="font-family:monospace; font-size:12px; margin-top:2px; color:var(--text-dim);">
                            ${escapeHtml(ev.timestamp || 'Time unavailable')}
                        </div>
                    </div>
                    <div>
                        <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Detection Rule Match</span>
                        <div style="margin-top:2px;">
                            ${rulesHtml || '<span style="font-size:11.5px; color:var(--text-muted);">None (Normal Baseline)</span>'}
                        </div>
                    </div>
                </div>

                <div style="margin-bottom:12px;">
                    <span style="font-size:11px; font-weight:700; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px;">Forensic Assessment:</span>
                    <div style="font-size:12.5px; color:#e2e8f0; background:rgba(2,132,199,0.08); border-left:3px solid var(--accent-cyan); padding:8px 12px; border-radius:4px; margin-top:4px;">
                        ${assessment}
                    </div>
                </div>

                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <span style="font-size:11px; font-weight:700; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px;">Raw Evidence Log:</span>
                        <button class="btn btn-secondary btn-sm" onclick="copyRawLogPayload('modal-raw-log-${idx}')">&#128203; Copy Raw Log</button>
                    </div>
                    <div class="raw-log-container" style="margin-top:2px; margin-bottom:8px;">
                        <pre id="modal-raw-log-${idx}" class="raw-log-text">${escapeHtml(ev.raw_log || ev.message || 'No raw log line captured.')}</pre>
                    </div>
                </div>

                <div style="border-top:1px solid rgba(255,255,255,0.06); padding-top:8px; margin-top:8px; font-size:12px; color:var(--text-muted);">
                    <strong style="color:var(--accent-cyan);">SOC Action:</strong> ${recAction}
                </div>
            </div>
        </div>
    `;
}

function closeIncidentModal() {
    document.getElementById('incident-modal').classList.remove('active');
}

// ================= 6. IOC Findings View =================
async function loadIOCs() {
    if (!state.currentRunId) {
        document.getElementById('iocs-tbody').innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">No analysis run selected.</td></tr>';
        return;
    }

    try {
        const res = await fetch(`/api/iocs?run_id=${state.currentRunId}`);
        const iocs = await res.json();
        const tbody = document.getElementById('iocs-tbody');

        if (!iocs || iocs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No Indicators of Compromise observed.</td></tr>';
            return;
        }

        let html = '';
        iocs.forEach(ioc => {
            const suspBadge = ioc.is_suspicious 
                ? '<span class="badge badge-critical">Suspicious</span>' 
                : '<span class="badge badge-low">Observed</span>';

            html += `
                <tr>
                    <td><span class="badge badge-tag">${ioc.ioc_type}</span></td>
                    <td><code>${escapeHtml(ioc.ioc_value)}</code></td>
                    <td>${suspBadge}</td>
                    <td>${escapeHtml(ioc.context || '')}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="copyText('${escapeHtml(ioc.ioc_value)}')">Copy</button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        console.error('Error loading IOCs:', err);
    }
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied ${text} to clipboard`, 'success');
    });
}

// ================= 7. Interactive Attack Timeline View =================
async function loadTimeline() {
    const container = document.getElementById('timeline-display');
    if (!container) return;

    if (!state.currentRunId) {
        container.innerHTML = `
            <div class="card" style="padding:32px; text-align:center; color:var(--text-muted);">
                <h3>No Analysis Run Active</h3>
                <p style="margin-top:6px; font-size:13px;">Please ingest a log file or analyze a synthetic scenario from the Upload tab to view attack progression timelines.</p>
            </div>
        `;
        return;
    }

    try {
        const res = await fetch(`/api/incidents?run_id=${state.currentRunId}`);
        const incidents = await res.json();

        if (!incidents || incidents.length === 0) {
            container.innerHTML = `
                <div class="card" style="padding:36px; text-align:center; color:var(--text-muted);">
                    <div style="font-size:36px; margin-bottom:8px;">&#10004;</div>
                    <h3 style="color:#34d399; margin-bottom:6px;">No Correlated Attack Timelines</h3>
                    <p style="font-size:13.5px; max-width:550px; margin:0 auto;">
                        The events in this log run did not trigger any correlated attack chains or rule thresholds. System baseline remains healthy.
                    </p>
                </div>
            `;
            return;
        }

        state.timelineState = state.timelineState || {};
        state.timelineState.incidents = incidents;

        // Select active incident
        const currentActiveId = state.timelineState.activeIncidentId;
        const exists = incidents.some(inc => inc.id === currentActiveId);
        if (!exists) {
            state.timelineState.activeIncidentId = incidents[0].id;
            state.timelineState.selectedEventIndex = 0;
            state.timelineState.activeFilter = 'ALL';
        }

        await renderActiveTimelineView();
    } catch (err) {
        console.error('Error loading attack timeline:', err);
        container.innerHTML = `
            <div class="card" style="padding:24px; text-align:center; color:#ef4444;">
                <p>Failed to load attack timeline: ${escapeHtml(err.message)}</p>
            </div>
        `;
    }
}

async function selectTimelineIncident(incidentId) {
    if (!state.timelineState) return;
    state.timelineState.activeIncidentId = incidentId;
    state.timelineState.selectedEventIndex = 0;
    state.timelineState.activeFilter = 'ALL';
    await renderActiveTimelineView();
}

async function renderActiveTimelineView() {
    const container = document.getElementById('timeline-display');
    if (!container || !state.timelineState) return;

    const incidents = state.timelineState.incidents || [];
    const activeId = state.timelineState.activeIncidentId;

    // Fetch full incident details with timeline events
    const incRes = await fetch(`/api/incidents/${activeId}`);
    const activeInc = await incRes.json();
    if (!incRes.ok) throw new Error(activeInc.detail || 'Incident details unavailable');

    state.timelineState.activeIncidentDetail = activeInc;
    const events = activeInc.timeline || [];

    // 1. Incident Selector (if multiple incidents or tab header)
    let selectorHtml = '';
    if (incidents.length > 1) {
        selectorHtml = `
            <div class="timeline-incident-selector">
                ${incidents.map(inc => {
                    const isActive = inc.id === activeId;
                    const sev = (inc.risk_level || 'LOW').toLowerCase();
                    return `
                        <button class="timeline-incident-tab ${isActive ? 'active' : ''}" onclick="selectTimelineIncident(${inc.id})">
                            <span class="badge badge-${sev}">${inc.risk_level}</span>
                            <span>${escapeHtml(inc.incident_code)}: ${escapeHtml(inc.title)}</span>
                        </button>
                    `;
                }).join('')}
            </div>
        `;
    }

    // 2. Correlation Ribbon & Stages
    const sevClass = (activeInc.risk_level || 'LOW').toLowerCase();
    const rawPattern = activeInc.attack_pattern || 'Initial Telemetry';
    const patternSteps = rawPattern.split(/->|→|&rarr;/).map(s => s.trim()).filter(Boolean);

    let stagesHtml = '';
    patternSteps.forEach((step, idx) => {
        stagesHtml += `<div class="stage-node"><span style="color:#38bdf8;">Stage ${idx + 1}:</span> ${escapeHtml(step)}</div>`;
        if (idx < patternSteps.length - 1) {
            stagesHtml += `<span class="stage-arrow">&rarr;</span>`;
        }
    });

    const factors = activeInc.contributing_factors || [];
    const factorsHtml = factors.map(f => `
        <span class="badge badge-tag" style="background:rgba(251,191,36,0.1); border-color:rgba(251,191,36,0.3); color:#fbbf24;">
            ${escapeHtml(f)}
        </span>
    `).join(' ');

    const ribbonHtml = `
        <div class="correlation-ribbon">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap;">
                <div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span class="badge badge-tag" style="font-size:12px;">${escapeHtml(activeInc.incident_code)}</span>
                        <h3 style="font-size:16px; margin:0; color:#fff;">${escapeHtml(activeInc.title)}</h3>
                    </div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:6px;">
                        Target Entity: Source IP <code>${escapeHtml(activeInc.source_ip || 'N/A')}</code> &bull;
                        User Account <code>${escapeHtml(activeInc.username || 'N/A')}</code> &bull;
                        Observation Window: <code>${escapeHtml(activeInc.first_observed || 'N/A')}</code> to <code>${escapeHtml(activeInc.last_observed || 'N/A')}</code>
                    </div>
                </div>
                <div>
                    <span class="badge badge-${sevClass}" style="font-size:13px; padding:6px 14px;">
                        Risk: ${escapeHtml(activeInc.risk_level)} (${activeInc.risk_score}/100)
                    </span>
                </div>
            </div>

            <div style="margin-top:14px; border-top:1px solid rgba(255,255,255,0.06); padding-top:12px;">
                <span style="font-size:11px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); font-weight:700;">Correlated Attack Pattern Progression:</span>
                <div class="correlation-stages">
                    ${stagesHtml || '<div class="stage-node">Single Stage Telemetry</div>'}
                </div>
            </div>

            <div style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <span style="font-size:11px; color:#fbbf24; font-weight:700; text-transform:uppercase;">Contributing Risk Factors:</span>
                    ${factorsHtml || '<span style="font-size:12px; color:var(--text-muted);">Standard Baseline</span>'}
                </div>
                <div style="font-size:11.5px; color:var(--text-dim);">
                    <span style="color:var(--accent-cyan); font-weight:600;">Correlation Basis:</span> Deterministic entity grouping &bull; ${events.length} chronological events
                </div>
            </div>
        </div>
    `;

    // 3. Split Workspace: Left Stream + Right Inspector
    const currentFilter = state.timelineState.activeFilter || 'ALL';
    const triggersCount = events.filter(e => {
        const cls = getEventClassification(e);
        return cls.isTrigger;
    }).length;
    const suspiciousCount = events.filter(e => {
        const cls = getEventClassification(e);
        return cls.isSuspicious;
    }).length;

    // Filter events
    let visibleEvents = [];
    events.forEach((ev, originalIndex) => {
        const cls = getEventClassification(ev);
        let match = false;
        if (currentFilter === 'ALL') match = true;
        else if (currentFilter === 'TRIGGERS' && cls.isTrigger) match = true;
        else if (currentFilter === 'SUSPICIOUS' && cls.isSuspicious) match = true;

        if (match) {
            visibleEvents.push({ event: ev, index: originalIndex });
        }
    });

    // Determine selected index
    let selIdx = state.timelineState.selectedEventIndex || 0;
    if (visibleEvents.length > 0 && !visibleEvents.some(v => v.index === selIdx)) {
        selIdx = visibleEvents[0].index;
        state.timelineState.selectedEventIndex = selIdx;
    }

    // Render Stream Event Cards
    let streamCardsHtml = '';
    if (visibleEvents.length === 0) {
        streamCardsHtml = `<div style="text-align:center; padding:30px; color:var(--text-muted);">No events match the selected filter.</div>`;
    } else {
        visibleEvents.forEach(({ event: ev, index: origIdx }) => {
            const isSelected = origIdx === selIdx;
            const cls = getEventClassification(ev);
            const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
            const rulesTagHtml = rules.map(r => `<span class="badge badge-tag" style="font-size:10px;">${escapeHtml(r)}</span>`).join(' ');

            streamCardsHtml += `
                <div class="timeline-event-card ${isSelected ? 'selected' : ''}" id="timeline-card-${origIdx}" onclick="selectTimelineStreamEvent(${origIdx})">
                    <div class="timeline-event-header">
                        <div style="display:flex; align-items:center; gap:6px;">
                            <span class="timeline-step-badge">#${origIdx + 1}</span>
                            <span class="badge ${cls.badgeClass}">${cls.category}</span>
                        </div>
                        <span class="timeline-event-time">${escapeHtml(ev.timestamp || 'N/A')}</span>
                    </div>
                    <div class="timeline-event-body">
                        <strong style="color:var(--accent-cyan); font-size:12.5px;">${escapeHtml(ev.event_type || 'EVENT')}</strong>
                        <div style="color:var(--text-main); font-size:12px; margin-top:2px;">${escapeHtml(ev.message || '')}</div>
                    </div>
                    <div class="timeline-event-footer">
                        <div>
                            <span>IP: <code>${escapeHtml(ev.source_ip || '-')}</code></span>
                            <span style="margin: 0 4px;">&bull;</span>
                            <span>User: <code>${escapeHtml(ev.username || '-')}</code></span>
                        </div>
                        <div>${rulesTagHtml}</div>
                    </div>
                </div>
            `;
        });
    }

    const layoutHtml = `
        <div class="timeline-layout">
            <!-- Left Stream -->
            <div class="timeline-stream-card">
                <div class="timeline-filter-bar">
                    <button class="timeline-filter-btn ${currentFilter === 'ALL' ? 'active' : ''}" onclick="setTimelineFilter('ALL')">
                        All Events (${events.length})
                    </button>
                    <button class="timeline-filter-btn ${currentFilter === 'TRIGGERS' ? 'active' : ''}" onclick="setTimelineFilter('TRIGGERS')">
                        Detection Triggers (${triggersCount})
                    </button>
                    <button class="timeline-filter-btn ${currentFilter === 'SUSPICIOUS' ? 'active' : ''}" onclick="setTimelineFilter('SUSPICIOUS')">
                        Suspicious / Anomalies (${suspiciousCount})
                    </button>
                </div>
                <div class="timeline-stream" id="timeline-stream-container">
                    ${streamCardsHtml}
                </div>
            </div>

            <!-- Right Inspector -->
            <div class="timeline-inspector-card timeline-inspector-pane" id="timeline-inspector-container">
                <!-- Injected by renderTimelineInspector -->
            </div>
        </div>
    `;

    container.innerHTML = selectorHtml + ribbonHtml + layoutHtml;

    // Render inspector for selected event
    if (events[selIdx]) {
        renderTimelineInspector(events[selIdx], selIdx, events.length);
    }
}

function setTimelineFilter(filterType) {
    if (!state.timelineState) return;
    state.timelineState.activeFilter = filterType;
    renderActiveTimelineView();
}

function selectTimelineStreamEvent(idx) {
    if (!state.timelineState || !state.timelineState.activeIncidentDetail) return;
    state.timelineState.selectedEventIndex = idx;

    // Update active card styling
    document.querySelectorAll('.timeline-event-card').forEach(card => card.classList.remove('selected'));
    const targetCard = document.getElementById(`timeline-card-${idx}`);
    if (targetCard) targetCard.classList.add('selected');

    const events = state.timelineState.activeIncidentDetail.timeline || [];
    if (events[idx]) {
        renderTimelineInspector(events[idx], idx, events.length);
    }
}

function renderTimelineInspector(ev, idx, total) {
    const container = document.getElementById('timeline-inspector-container');
    if (!container || !ev) return;

    const cls = getEventClassification(ev);
    const ipClass = getIpClassification(ev.source_ip);
    const rules = (ev.extra_data && ev.extra_data.matched_rules) || [];
    const matchedRulesHtml = rules.map(r => `<span class="badge badge-tag">${escapeHtml(r)}</span>`).join(' ');
    const assessment = generateForensicAssessment(ev);
    const action = generateAnalystRecommendation(ev);

    container.innerHTML = `
        <div class="card-header" style="background:var(--bg-card-header); padding:12px 16px; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center;">
            <div>
                <strong style="font-size:13px; color:var(--text-main);">&#128269; Forensic Evidence Inspector</strong>
                <span style="font-size:11.5px; color:var(--text-muted); margin-left:8px;">Event #${idx + 1} of ${total}</span>
            </div>
            <span class="badge ${cls.badgeClass}">${cls.category}</span>
        </div>
        <div style="padding:16px;">
            <div style="margin-bottom:12px;">
                <h4 style="font-size:14px; color:#fff; margin-bottom:2px;">${escapeHtml(ev.event_type)}</h4>
                <div style="font-size:11.5px; font-family:monospace; color:var(--text-dim);">${escapeHtml(ev.timestamp || 'Timestamp unavailable')}</div>
            </div>

            <div class="inspector-meta-grid">
                <div>
                    <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Source IP</span>
                    <div style="font-family:monospace; font-size:12px; margin-top:2px;">
                        <code>${escapeHtml(ev.source_ip || 'N/A')}</code>
                        ${ipClass ? ipClass.badge : ''}
                    </div>
                </div>
                <div>
                    <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">User / Host</span>
                    <div style="font-family:monospace; font-size:12px; margin-top:2px;">
                        <code>${escapeHtml(ev.username || 'N/A')}</code>
                    </div>
                </div>
                <div>
                    <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Severity</span>
                    <div style="margin-top:2px;">
                        <span class="badge badge-${(ev.severity || 'LOW').toLowerCase()}">${ev.severity || 'LOW'}</span>
                    </div>
                </div>
                <div>
                    <span style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Detection Rule Match</span>
                    <div style="margin-top:2px;">
                        ${matchedRulesHtml || '<span style="color:var(--text-muted); font-size:12px;">None (Baseline)</span>'}
                    </div>
                </div>
            </div>

            <div style="margin-bottom:14px;">
                <span style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Forensic Assessment:</span>
                <div style="font-size:12.5px; color:#e2e8f0; background:rgba(2,132,199,0.08); border-left:3px solid var(--accent-cyan); padding:8px 12px; border-radius:4px; margin-top:4px;">
                    ${assessment}
                </div>
            </div>

            <div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <span style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Raw Telemetry Evidence:</span>
                    <button class="btn btn-secondary btn-sm" onclick="copyRawLogPayload('timeline-raw-log-${idx}')">&#128203; Copy Raw Log</button>
                </div>
                <div class="raw-log-container">
                    <pre id="timeline-raw-log-${idx}" class="raw-log-text">${escapeHtml(ev.raw_log || ev.message || 'No raw log line captured.')}</pre>
                </div>
            </div>

            <div style="margin-top:12px; padding-top:12px; border-top:1px solid var(--border-color);">
                <span style="font-size:11px; font-weight:700; color:var(--accent-blue); text-transform:uppercase; letter-spacing:0.5px;">Analyst Action Advice:</span>
                <div style="font-size:12px; color:var(--text-main); margin-top:4px;">
                    ${action}
                </div>
            </div>
        </div>
    `;
}

// ================= 8. Reports View =================
async function loadReportsView() {
    if (!state.currentRunId) {
        document.getElementById('reports-active-banner').innerHTML = '<p style="color:var(--text-muted);">No analysis run selected.</p>';
        return;
    }

    document.getElementById('reports-active-banner').innerHTML = `
        <div style="background:var(--bg-sidebar); border:1px solid var(--border-color); border-radius:8px; padding:18px; margin-bottom:20px;">
            <h3>Target Run: #${state.currentRunId}</h3>
            <p style="color:var(--text-muted); font-size:13px; margin:6px 0 16px 0;">
                Generate exportable incident analysis reports for audit and presentation.
            </p>
            <div style="display:flex; gap:12px;">
                <a href="/api/reports/${state.currentRunId}/html" target="_blank" class="btn btn-primary">
                    View / Print Executive HTML Report
                </a>
                <a href="/api/reports/${state.currentRunId}/json" class="btn btn-secondary">
                    Download Raw JSON Report
                </a>
            </div>
        </div>
    `;

    // Load past runs history
    try {
        const res = await fetch('/api/runs');
        const runs = await res.json();
        const tbody = document.getElementById('runs-history-tbody');
        let html = '';
        runs.forEach(r => {
            const isCurrent = r.id === state.currentRunId;
            html += `
                <tr style="${isCurrent ? 'background:rgba(2,132,199,0.1);' : ''}">
                    <td><strong>#${r.id}</strong></td>
                    <td><code>${escapeHtml(r.filename)}</code></td>
                    <td>${r.uploaded_at ? r.uploaded_at.replace('T', ' ').substring(0, 19) : '-'}</td>
                    <td>${r.total_events}</td>
                    <td>${r.total_incidents}</td>
                    <td><strong>${r.max_risk_score}</strong></td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="switchActiveRun(${r.id})">
                            ${isCurrent ? 'Active' : 'Switch'}
                        </button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        console.error('Error loading runs history:', err);
    }
}

function switchActiveRun(runId) {
    state.currentRunId = runId;
    loadInitialState();
    showToast(`Switched active analysis to Run #${runId}`, 'info');
}

// Utility function to escape HTML
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
