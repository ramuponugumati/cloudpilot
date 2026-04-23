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

    // Quick action buttons
    document.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            Chat.sendQuickAction(btn.dataset.action);
        });
    });

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
