/**
 * CloudPilot App — suite-based navigation with accordion behavior
 */

const SUITES = [
    {
        name: 'FinOps', icon: '💰', color: '#4a8c6f',
        skills: ['cost-radar', 'zombie-hunter', 'costopt-intelligence', 'database-optimizer'],
        action: 'Run FinOps suite: cost-radar, zombie-hunter, costopt-intelligence, database-optimizer',
    },
    {
        name: 'Security', icon: '🛡️', color: '#5a9a7e',
        skills: ['security-posture', 'data-security', 'secrets-hygiene', 'sg-chain-analyzer'],
        action: 'Run Security suite: security-posture, data-security, secrets-hygiene, sg-chain-analyzer',
    },
    {
        name: 'Network', icon: '🌐', color: '#5e9485',
        skills: ['network-path-tracer', 'connectivity-diagnoser', 'network-topology', 'dns-cert-manager'],
        action: 'Run Network suite: network-path-tracer, connectivity-diagnoser, network-topology, dns-cert-manager',
    },
    {
        name: 'Platform', icon: '🏗️', color: '#508e74',
        skills: ['drift-detector', 'eks-optimizer', 'serverless-optimizer', 'arch-diagram', 'lifecycle-tracker'],
        action: 'Run Platform suite: drift-detector, eks-optimizer, serverless-optimizer, arch-diagram, lifecycle-tracker',
    },
    {
        name: 'Resilience', icon: '🔄', color: '#5b9080',
        skills: ['resiliency-gaps', 'backup-dr-posture', 'blast-radius', 'health-monitor', 'capacity-planner'],
        action: 'Run Resilience suite: resiliency-gaps, backup-dr-posture, blast-radius, health-monitor, capacity-planner',
    },
    {
        name: 'Governance', icon: '🏢', color: '#4d8a78',
        skills: ['tag-enforcer', 'quota-guardian', 'multi-account-governance', 'shadow-it-detector'],
        action: 'Run Governance suite: tag-enforcer, quota-guardian, multi-account-governance, shadow-it-detector',
    },
    {
        name: 'Modernization', icon: '🚀', color: '#55967a',
        skills: ['modernization-advisor', 'event-analysis'],
        action: 'Run Modernization suite: modernization-advisor, event-analysis',
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
