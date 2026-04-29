/**
 * CloudPilot App — suite-based navigation with accordion behavior
 */

const SUITES = [
    {
        name: 'FinOps', icon: '💰', color: '#d97706',
        skills: ['cost-radar', 'zombie-hunter', 'costopt-intelligence', 'database-optimizer'],
        action: 'Use the run_suite tool with skill_names: cost-radar, zombie-hunter, costopt-intelligence, database-optimizer',
    },
    {
        name: 'Security', icon: '🛡️', color: '#dc2626',
        skills: ['security-posture', 'data-security', 'secrets-hygiene', 'sg-chain-analyzer'],
        action: 'Use the run_suite tool with skill_names: security-posture, data-security, secrets-hygiene, sg-chain-analyzer',
    },
    {
        name: 'Network', icon: '🌐', color: '#2563eb',
        skills: ['network-path-tracer', 'connectivity-diagnoser', 'network-topology', 'dns-cert-manager'],
        action: 'Use the run_suite tool with skill_names: network-path-tracer, connectivity-diagnoser, network-topology, dns-cert-manager',
    },
    {
        name: 'Platform', icon: '🏗️', color: '#7c3aed',
        skills: ['drift-detector', 'eks-optimizer', 'serverless-optimizer', 'arch-diagram', 'lifecycle-tracker'],
        action: 'Use the run_suite tool with skill_names: drift-detector, eks-optimizer, serverless-optimizer, arch-diagram, lifecycle-tracker',
    },
    {
        name: 'Resilience', icon: '🔄', color: '#0891b2',
        skills: ['resiliency-gaps', 'backup-dr-posture', 'blast-radius', 'health-monitor', 'capacity-planner'],
        action: 'Use the run_suite tool with skill_names: resiliency-gaps, backup-dr-posture, blast-radius, health-monitor, capacity-planner',
    },
    {
        name: 'Governance', icon: '🏢', color: '#4f46e5',
        skills: ['tag-enforcer', 'quota-guardian', 'multi-account-governance', 'shadow-it-detector'],
        action: 'Use the run_suite tool with skill_names: tag-enforcer, quota-guardian, multi-account-governance, shadow-it-detector',
    },
    {
        name: 'Modernization', icon: '🚀', color: '#059669',
        skills: ['modernization-advisor', 'event-analysis'],
        action: 'Use the run_suite tool with skill_names: modernization-advisor, event-analysis',
    },
];

const SKILL_ICONS = {
    'cost-radar': '📡', 'zombie-hunter': '🧟', 'security-posture': '🛡️',
    'capacity-planner': '📊', 'event-analysis': '🔍', 'resiliency-gaps': '🏗️',
    'tag-enforcer': '🏷️', 'lifecycle-tracker': '⏳', 'health-monitor': '🏥',
    'quota-guardian': '📏', 'arch-diagram': '🗺️', 'costopt-intelligence': '💡',
    'network-path-tracer': '🔀', 'sg-chain-analyzer': '🔗', 'connectivity-diagnoser': '🔌',
    'network-topology': '🕸️', 'drift-detector': '🔄', 'backup-dr-posture': '💾',
    'data-security': '🔐', 'eks-optimizer': '☸️', 'secrets-hygiene': '🔑',
    'serverless-optimizer': '⚡', 'dns-cert-manager': '📜', 'database-optimizer': '🗄️',
    'multi-account-governance': '🏢', 'modernization-advisor': '🚀',
    'blast-radius': '💥', 'shadow-it-detector': '👻',
};

document.addEventListener('DOMContentLoaded', async () => {
    Chat.init();

    // Render suites with accordion behavior
    const suitesList = document.getElementById('suites-list');
    const suiteCards = [];

    if (suitesList) {
        SUITES.forEach((suite, idx) => {
            const el = document.createElement('div');
            el.className = 'suite-card';
            el.style.setProperty('--suite-color', suite.color);
            el.innerHTML = `
                <div class="suite-header">
                    <span class="suite-icon">${suite.icon}</span>
                    <span class="suite-name">${suite.name}</span>
                    <span class="suite-count">${suite.skills.length}</span>
                    <span class="suite-chevron">▸</span>
                </div>
                <div class="suite-skills">
                    ${suite.skills.map(s =>
                        `<div class="suite-skill" data-skill="${s}">${SKILL_ICONS[s] || '📎'} ${s}</div>`
                    ).join('')}
                    <div class="suite-run-btn" data-idx="${idx}">▶ Run entire suite</div>
                </div>
            `;
            suiteCards.push(el);

            // Accordion: click header toggles this, closes others
            el.querySelector('.suite-header').addEventListener('click', () => {
                const isOpen = el.classList.contains('expanded');
                // Close all
                suiteCards.forEach(card => {
                    card.classList.remove('expanded');
                    card.querySelector('.suite-skills').style.maxHeight = '0';
                    card.querySelector('.suite-chevron').textContent = '▸';
                });
                // Open clicked (if it was closed)
                if (!isOpen) {
                    el.classList.add('expanded');
                    const skillsDiv = el.querySelector('.suite-skills');
                    skillsDiv.style.maxHeight = skillsDiv.scrollHeight + 'px';
                    el.querySelector('.suite-chevron').textContent = '▾';
                }
            });

            // Run suite button
            el.querySelector('.suite-run-btn').addEventListener('click', (e) => {
                e.stopPropagation();
                Chat.sendQuickAction(suite.action);
            });

            // Individual skill clicks
            el.querySelectorAll('.suite-skill').forEach(skillEl => {
                skillEl.addEventListener('click', (e) => {
                    e.stopPropagation();
                    Chat.sendQuickAction(`Run the ${skillEl.dataset.skill} skill`);
                });
            });

            suitesList.appendChild(el);
        });
    }

    // Quick action buttons (skip monitoring buttons which have their own handlers)
    document.querySelectorAll('.action-btn[data-action]').forEach(btn => {
        btn.addEventListener('click', () => {
            Chat.sendQuickAction(btn.dataset.action);
        });
    });

    // Monitoring buttons
    const historyBtn = document.getElementById('btn-history');
    if (historyBtn) {
        historyBtn.addEventListener('click', async () => {
            try {
                const records = await API._fetch('/api/monitoring/history?limit=20');
                if (!records || records.length === 0) {
                    Chat.addMessage('assistant', 'No scan history yet. Run a suite scan first, or start the scheduler with `cloudpilot monitor`.');
                    return;
                }
                let md = '**📊 Scan History** (last 20 runs)\n\n';
                const sevEmoji = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
                for (const r of records) {
                    const ts = new Date(r.timestamp).toLocaleString();
                    const sev = [];
                    if (r.critical_count) sev.push(`🔴${r.critical_count}`);
                    if (r.high_count) sev.push(`🟠${r.high_count}`);
                    if (r.medium_count) sev.push(`🟡${r.medium_count}`);
                    const sevStr = sev.length ? sev.join(' ') : '✅ clean';
                    const impact = r.total_impact > 0 ? ` · $${r.total_impact.toFixed(2)}/mo` : '';
                    md += `• **${r.suite}** (${r.trigger}) — ${r.total_findings} findings ${sevStr}${impact} — ${ts} *(${r.duration_seconds}s)*\n`;
                }
                Chat.addMessage('assistant', md);
            } catch (e) {
                Chat.addMessage('assistant', `⚠️ Could not load history: ${e.message}`);
            }
        });
    }

    const schedulerBtn = document.getElementById('btn-scheduler');
    if (schedulerBtn) {
        schedulerBtn.addEventListener('click', async () => {
            try {
                const status = await API._fetch('/api/monitoring/scheduler');
                let md = '**⏰ Scheduler Status**\n\n';
                md += `Running: **${status.running ? '✅ Yes' : '❌ No'}**\n`;
                md += `History records: **${status.history_count}**\n\n`;
                if (Object.keys(status.schedules).length > 0) {
                    md += '| Suite | Interval |\n|-------|----------|\n';
                    for (const [name, sched] of Object.entries(status.schedules)) {
                        md += `| ${name} | Every ${sched.interval_hours}h |\n`;
                    }
                } else {
                    md += 'No schedules configured. Start with `cloudpilot monitor` CLI command.';
                }
                Chat.addMessage('assistant', md);
            } catch (e) {
                Chat.addMessage('assistant', `⚠️ Could not load scheduler status: ${e.message}`);
            }
        });
    }

    // Real-time monitoring
    let realtimeWs = null;
    let realtime_events_buffer = [];  // Store events for export
    const realtimeBtn = document.getElementById('btn-realtime');
    const liveSection = document.getElementById('live-events-section');
    const liveEvents = document.getElementById('live-events');
    const liveDot = document.getElementById('live-dot');
    const sevEmoji = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
    const typeIcons = {cloudtrail:'🔍',health:'🏥',alarm:'🔔',finding:'📋',heartbeat:'💓'};

    if (realtimeBtn) {
        realtimeBtn.addEventListener('click', async () => {
            if (realtimeBtn.disabled) return;

            if (realtimeWs && realtimeWs.readyState === WebSocket.OPEN) {
                // Already connected — just inform
                Chat.addMessage('assistant', '📡 Live events are already recording. Events appear in the sidebar feed.');
                return;
            }

            // Disable button immediately
            realtimeBtn.disabled = true;
            realtimeBtn.textContent = '⏳ Connecting...';
            realtimeBtn.style.opacity = '0.6';

            // Start the server-side poller
            try {
                await API._fetch('/api/monitoring/realtime/start?poll_interval=60', {method:'POST'});
            } catch(e) {
                Chat.addMessage('assistant', `⚠️ Could not start real-time monitor: ${e.message}`);
                realtimeBtn.disabled = false;
                realtimeBtn.textContent = '📡 Live Events';
                realtimeBtn.style.opacity = '1';
                return;
            }

            // Connect WebSocket
            const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            realtimeWs = new WebSocket(`${wsProto}//${location.host}/ws/realtime`);

            realtimeWs.onopen = () => {
                liveSection.style.display = 'block';
                realtimeBtn.textContent = '🔴 Recording Live Events';
                realtimeBtn.disabled = true;
                realtimeBtn.style.opacity = '0.7';
                Chat.addMessage('assistant', '📡 Real-time monitoring **started** — recording CloudTrail, Health Dashboard, and CloudWatch alarm events. Watch the sidebar for live updates.');
            };

            realtimeWs.onmessage = (msg) => {
                try {
                    const evt = JSON.parse(msg.data);
                    if (evt.event_type === 'heartbeat') {
                        // Just pulse the dot
                        liveDot.style.animation = 'none';
                        requestAnimationFrame(() => liveDot.style.animation = '');
                        return;
                    }
                    // Add event to live feed
                    const el = document.createElement('div');
                    el.className = `live-event ${evt.severity}`;
                    const icon = typeIcons[evt.event_type] || '📋';
                    const emoji = sevEmoji[evt.severity] || '⚪';
                    const time = new Date(evt.timestamp).toLocaleTimeString();
                    el.innerHTML = `
                        <div class="live-event-title">${emoji} ${icon} ${evt.title}</div>
                        <div class="live-event-meta">
                            <span class="live-event-type">${evt.event_type}</span>
                            ${evt.region} · ${time}
                        </div>
                    `;
                    liveEvents.prepend(el);
                    realtime_events_buffer.push(evt);  // Buffer for export
                    // Cap at 50 events
                    while (liveEvents.children.length > 50) {
                        liveEvents.removeChild(liveEvents.lastChild);
                    }
                    // Flash critical/high events in chat
                    if (evt.severity === 'critical') {
                        Chat.addMessage('assistant', `🔴 **CRITICAL EVENT:** ${evt.title}\n${evt.description}\nRegion: ${evt.region} · Source: ${evt.source}`);
                    }
                } catch(e) {}
            };

            realtimeWs.onclose = () => {
                liveSection.style.display = 'none';
                realtimeBtn.textContent = '📡 Live Events';
                realtimeBtn.style.setProperty('--btn-color', '#dc2626');
            };
        });
    }

    // Health check
    try {
        await API.health();
        document.getElementById('status-text').textContent = '⚡ 28 Skills Ready';
    } catch (e) {
        document.getElementById('status-indicator').className = 'status-dot';
        document.getElementById('status-indicator').style.background = '#ff5252';
        document.getElementById('status-text').textContent = 'Disconnected';
    }

    // --- Export handlers ---
    function downloadFile(filename, content, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function toCsv(rows, headers) {
        const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const lines = [headers.map(escape).join(',')];
        for (const row of rows) {
            lines.push(headers.map(h => escape(row[h])).join(','));
        }
        return lines.join('\n');
    }

    // Export live events as CSV
    document.getElementById('btn-export-events')?.addEventListener('click', () => {
        const events = (realtimeWs?._eventBuffer || []).length
            ? realtimeWs._eventBuffer
            : Array.from(document.querySelectorAll('.live-event')).map(el => ({
                timestamp: el.querySelector('.live-event-meta')?.textContent?.trim() || '',
                title: el.querySelector('.live-event-title')?.textContent?.trim() || '',
                type: el.querySelector('.live-event-type')?.textContent?.trim() || '',
            }));
        // Use the monitor's event buffer if available
        if (realtime_events_buffer.length > 0) {
            const headers = ['timestamp', 'event_type', 'severity', 'title', 'description', 'source', 'region', 'resource_id'];
            const csv = toCsv(realtime_events_buffer, headers);
            downloadFile(`cloudpilot-events-${new Date().toISOString().slice(0,10)}.csv`, csv, 'text/csv');
            Chat.addMessage('assistant', `⬇️ Exported **${realtime_events_buffer.length} live events** to CSV.`);
        } else {
            Chat.addMessage('assistant', 'No live events to export yet. Start the live feed first.');
        }
    });

    // Export findings as CSV
    document.getElementById('btn-export-findings-csv')?.addEventListener('click', async () => {
        try {
            const data = await API._fetch('/api/monitoring/history?limit=1');
            if (data.length === 0) {
                // Try getting findings from the agent's store via summary
                Chat.addMessage('assistant', 'No scan history found. Run a scan first, then export.');
                return;
            }
            const record = await API._fetch(`/api/monitoring/history/${data[0].id}`);
            const findings = record.findings || [];
            if (findings.length === 0) {
                Chat.addMessage('assistant', 'Latest scan had no findings to export.');
                return;
            }
            const headers = ['skill', 'title', 'severity', 'description', 'resource_id', 'region', 'monthly_impact', 'recommended_action'];
            const csv = toCsv(findings, headers);
            downloadFile(`cloudpilot-findings-${new Date().toISOString().slice(0,10)}.csv`, csv, 'text/csv');
            Chat.addMessage('assistant', `⬇️ Exported **${findings.length} findings** from latest scan to CSV.`);
        } catch (e) {
            Chat.addMessage('assistant', `⚠️ Export failed: ${e.message}`);
        }
    });

    // Export findings as JSON
    document.getElementById('btn-export-findings-json')?.addEventListener('click', async () => {
        try {
            const data = await API._fetch('/api/monitoring/history?limit=1');
            if (data.length === 0) {
                Chat.addMessage('assistant', 'No scan history found. Run a scan first, then export.');
                return;
            }
            const record = await API._fetch(`/api/monitoring/history/${data[0].id}`);
            const json = JSON.stringify(record, null, 2);
            downloadFile(`cloudpilot-scan-${data[0].id}.json`, json, 'application/json');
            Chat.addMessage('assistant', `⬇️ Exported full scan record **${data[0].id}** as JSON.`);
        } catch (e) {
            Chat.addMessage('assistant', `⚠️ Export failed: ${e.message}`);
        }
    });

    // Export chat transcript
    document.getElementById('btn-export-chat')?.addEventListener('click', () => {
        const messages = Chat._history || [];
        if (messages.length === 0) {
            Chat.addMessage('assistant', 'No chat messages to export.');
            return;
        }
        let md = `# CloudPilot Chat Transcript\n# Exported: ${new Date().toLocaleString()}\n\n`;
        for (const msg of messages) {
            const label = msg.role === 'user' ? '**You:**' : '**CloudPilot:**';
            md += `${label}\n${msg.content}\n\n---\n\n`;
        }
        downloadFile(`cloudpilot-chat-${new Date().toISOString().slice(0,10)}.md`, md, 'text/markdown');
        Chat.addMessage('assistant', `⬇️ Exported **${messages.length} messages** as Markdown.`);
    });
});
