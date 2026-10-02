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
    eventsFilter: {
        severity: '',
        eventType: '',
        search: ''
    }
};

// Initialization on DOM Content Loaded
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUploadHandlers();
    loadSamplesList();
    loadInitialState();
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

// ================= Initial State Loader =================
async function loadInitialState() {
    try {
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

        // Load preview incidents on dashboard
        if (state.currentRunId) {
            const incRes = await fetch(`/api/incidents?run_id=${state.currentRunId}`);
            const incidents = await incRes.json();
            renderDashboardIncidents(incidents);
        } else {
            renderDashboardIncidents([]);
        }
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
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
        const container = document.getElementById('incidents-container');

        if (!incidents || incidents.length === 0) {
            container.innerHTML = `
                <div class="card" style="padding:30px; text-align:center; color:var(--text-muted);">
                    <h3>No Security Incidents Detected</h3>
                    <p>The events in this log run did not trigger any correlated attack chains or rule thresholds.</p>
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
    } catch (err) {
        console.error('Error loading incidents:', err);
    }
}

// ================= 5. Incident Details Modal =================
async function openIncidentModal(incidentId) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        const inc = await res.json();
        if (!res.ok) throw new Error(inc.detail || 'Incident not found');

        document.getElementById('modal-incident-title').textContent = `${inc.incident_code}: ${inc.title}`;
        
        const sevClass = inc.risk_level.toLowerCase();
        let factorsHtml = (inc.contributing_factors || []).map(f => `<li><code>${f}</code></li>`).join('');
        let recsHtml = (inc.recommendations || []).map(r => `<li>${r}</li>`).join('');
        let rulesHtml = (inc.rules_triggered || []).map(r => `<span class="badge badge-tag">${r}</span>`).join(' ');

        // Timeline table rows
        let timelineRows = '';
        (inc.timeline || []).forEach(ev => {
            timelineRows += `
                <tr>
                    <td><code>${ev.timestamp || 'N/A'}</code></td>
                    <td><strong>${ev.event_type}</strong></td>
                    <td><code>${ev.source_ip || '-'}</code></td>
                    <td><code>${ev.username || '-'}</code></td>
                    <td>${escapeHtml(ev.message)}</td>
                </tr>
            `;
        });

        const modalContent = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <div>
                    <span class="badge badge-tag">${inc.incident_type}</span>
                    <span style="margin-left:10px; font-size:13px; color:var(--text-muted);">Observed: ${inc.first_observed || 'N/A'} to ${inc.last_observed || 'N/A'}</span>
                </div>
                <span class="badge badge-${sevClass}" style="font-size:13px; padding:6px 14px;">Risk: ${inc.risk_level} (${inc.risk_score}/100)</span>
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

            <div>
                <h4 style="font-size:13px; margin-bottom:8px;">Chronological Incident Timeline (${(inc.timeline || []).length} events):</h4>
                <div class="table-wrapper">
                    <table class="soc-table">
                        <thead>
                            <tr><th>Timestamp</th><th>Event Type</th><th>Source IP</th><th>User</th><th>Message</th></tr>
                        </thead>
                        <tbody>${timelineRows || '<tr><td colspan="5">No timeline events available.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        `;

        document.getElementById('modal-incident-body').innerHTML = modalContent;
        document.getElementById('incident-modal').classList.add('active');
    } catch (err) {
        showToast(err.message, 'error');
    }
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

// ================= 7. Timeline View =================
async function loadTimeline() {
    if (!state.currentRunId) {
        document.getElementById('timeline-display').innerHTML = '<p style="padding:20px; color:var(--text-muted);">No analysis run selected.</p>';
        return;
    }

    try {
        const res = await fetch(`/api/incidents?run_id=${state.currentRunId}`);
        const incidents = await res.json();
        const container = document.getElementById('timeline-display');

        if (!incidents || incidents.length === 0) {
            container.innerHTML = '<p style="padding:20px; color:var(--text-muted);">No correlated incident timelines available.</p>';
            return;
        }

        let html = '';
        for (const inc of incidents) {
            const fullRes = await fetch(`/api/incidents/${inc.id}`);
            const fullInc = await fullRes.json();
            const sevClass = fullInc.risk_level.toLowerCase();

            let itemsHtml = '';
            (fullInc.timeline || []).forEach(ev => {
                const bulletClass = ev.severity ? ev.severity.toLowerCase() : 'low';
                itemsHtml += `
                    <div class="timeline-item">
                        <div class="timeline-bullet ${bulletClass}"></div>
                        <div class="timeline-content">
                            <div class="timeline-time">${ev.timestamp || 'Time unavailable'}</div>
                            <div class="timeline-title">${ev.event_type} &bull; <span style="font-weight:normal; color:var(--text-muted);">${ev.source_ip || 'No IP'}</span></div>
                            <div style="font-size:12.5px; color:var(--text-main);">${escapeHtml(ev.message)}</div>
                        </div>
                    </div>
                `;
            });

            html += `
                <div class="card" style="margin-bottom:24px;">
                    <div class="card-header">
                        <span class="card-title">${fullInc.incident_code}: ${escapeHtml(fullInc.title)}</span>
                        <span class="badge badge-${sevClass}">${fullInc.risk_level} (${fullInc.risk_score}/100)</span>
                    </div>
                    <div class="card-body">
                        <div class="attack-chain-banner" style="margin-bottom:20px;">
                            ${escapeHtml(fullInc.attack_pattern)}
                        </div>
                        <div class="timeline-container">
                            ${itemsHtml}
                        </div>
                    </div>
                </div>
            `;
        }
        container.innerHTML = html;
    } catch (err) {
        console.error('Error loading timeline:', err);
    }
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
