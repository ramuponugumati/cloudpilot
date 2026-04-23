/**
 * CloudPilot App — main entry point with suite-based navigation
 */

const SUITES = [
    {
        name: 'FinOps', icon: '💰', color: '#fbbf24',
        skills: ['cost-radar', 'zombie-hunter', 'costopt-intelligence', 'database-optimizer'],
        action: 'Run FinOps suite: cost-radar, zombie-hunter, costopt-intelligence, database-optimizer',
    },
    {
        name: 'Security', icon: '🛡️', color: '#00e676',
        skills: ['security-posture', 'data-security', 'secrets-hygiene', 'sg-chain-analyzer'],
        action: 'Run Security suite: security-posture, data-security, secrets-hygiene, sg-chain-analyzer',
    },
    {
        name: 'Network', icon: '🌐', color: '#60a5fa',
        skills: ['network-path-tracer', 'connectivity-diagnoser', 'network-topology', 'dns-cert-manager'],
        action: 'Run Network suite: network-path-tracer, connectivity-diagnoser, network-topology, dns-cert-manager',
    },
    {
        name: 'Platform', icon: '🏗️', color: '#a78bfa',
        skills: ['drift-detector', 'eks-optimizer', 'serverless-optimizer', 'arch-diagram', 'lifecycle-tracker'],
        action: 'Run Platform suite: drift-detector, eks-optimizer, serverless-optimizer, arch-diagram, lifecycle-tracker',
    },
    {
        name: 'Resilience', icon: '🔄', color: '#f472b6',
        skills: ['resiliency-gaps', 'backup-dr-posture', 'blast-radius', 'health-monitor', 'capacity-planner'],
        action: 'Run Resilience suite: resiliency-gaps, backup-dr-posture, blast-radius, health-monitor, capacity-planner',
    },
    {
        name: 'Governance', icon: '🏢', color: '#22d3ee',
        skills: ['tag-enforcer', 'quota-guardian', 'multi-account-governance', 'shadow-it-detector'],
        action: 'Run Governance suite: tag-enforcer, quota-guardian, multi-account-governance, shadow-it-detector',
    },
    {
        name: 'Modernization', icon: '🚀', color: '#34d399',
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

    // Render suites
    const suitesList = document.getElementById('suites-list');
    if (suitesList) {
        SUITES.forEach(suite => {
            const el = document.createElement('div');
            el.className = 'suite-card';
            el.style.setProperty('--suite-color', suite.color);
            el.innerHTML = `
                <div class="suite-header">
                    <span class="suite-icon">${suite.icon}</span>
                    <span class="suite-name">${suite.name}</span>
                    <span class="suite-count">${suite.skills.length}</span>
                </div>
                <div class="suite-skills" style="display:none">
                    ${suite.skills.map(s => `<div class="suite-skill" data-skill="${s}">${SKILL_ICONS[s] || '📎'} ${s}</div>`).join('')}
                </div>
            `;
            // Toggle expand
            el.querySelector('.suite-header').addEventListener('click', () => {
                const skillsDiv = el.querySelector('.suite-skills');
                skillsDiv.style.display = skillsDiv.style.display === 'none' ? 'block' : 'none';
                el.classList.toggle('expanded');
            });
            // Run suite on double-click header
            el.querySelector('.suite-header').addEventListener('dblclick', () => {
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

    // Load all skills into the flat list
    try {
        const skills = await API.listSkills();
        const skillsList = document.getElementById('skills-list');
        skills.forEach(s => {
            const el = document.createElement('div');
            el.className = 'skill-tag';
            el.style.setProperty('--skill-color', '#00b4ff');
            el.textContent = `${SKILL_ICONS[s.name] || '📎'} ${s.name}`;
            el.title = s.description;
            el.addEventListener('click', () => {
                Chat.sendQuickAction(`Run the ${s.name} skill`);
            });
            skillsList.appendChild(el);
        });
    } catch (e) {
        console.warn('Could not load skills:', e);
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
