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
    const realtimeBtn = document.getElementById('btn-realtime');
    const liveSection = document.getElementById('live-events-section');
    const liveEvents = document.getElementById('live-events');
    const liveDot = document.getElementById('live-dot');
    const sevEmoji = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
    const typeIcons = {cloudtrail:'🔍',health:'🏥',alarm:'🔔',finding:'📋',heartbeat:'💓'};

    if (realtimeBtn) {
        realtimeBtn.addEventListener('click', async () => {
            if (realtimeWs && realtimeWs.readyState === WebSocket.OPEN) {
                // Already connected — disconnect
                realtimeWs.close();
                realtimeWs = null;
                liveSection.style.display = 'none';
                realtimeBtn.textContent = '📡 Live Events';
                Chat.addMessage('assistant', '📡 Real-time monitoring **stopped**.');
                try { await API._fetch('/api/monitoring/realtime/stop', {method:'POST'}); } catch(e) {}
                return;
            }

            // Start the server-side poller
            try {
                await API._fetch('/api/monitoring/realtime/start?poll_interval=60', {method:'POST'});
            } catch(e) {
                Chat.addMessage('assistant', `⚠️ Could not start real-time monitor: ${e.message}`);
                return;
            }

            // Connect WebSocket
            const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            realtimeWs = new WebSocket(`${wsProto}//${location.host}/ws/realtime`);

            realtimeWs.onopen = () => {
                liveSection.style.display = 'block';
                realtimeBtn.textContent = '🔴 Stop Live';
                realtimeBtn.style.setProperty('--btn-color', '#dc2626');
                Chat.addMessage('assistant', '📡 Real-time monitoring **active** — watching CloudTrail, Health Dashboard, and CloudWatch alarms. Events will appear in the sidebar.');
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
});
