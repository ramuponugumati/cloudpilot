/**
 * CloudPilot App — main entry point, wires everything together
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize chat
    Chat.init();

    // Load skills list
    try {
        const skills = await API.listSkills();
        const skillsList = document.getElementById('skills-list');
        const icons = {
            'cost-radar': '📡', 'zombie-hunter': '🧟', 'security-posture': '🛡️',
            'capacity-planner': '📊', 'event-analysis': '🔍', 'resiliency-gaps': '🏗️',
            'tag-enforcer': '🏷️', 'lifecycle-tracker': '⏳', 'health-monitor': '🏥',
            'quota-guardian': '📏', 'arch-diagram': '🗺️', 'costopt-intelligence': '💡',
        };
        const skillColors = {
            'cost-radar': '#00b4ff', 'zombie-hunter': '#ff5252', 'security-posture': '#00e676',
            'capacity-planner': '#7c4dff', 'event-analysis': '#ff9100', 'resiliency-gaps': '#e040fb',
            'tag-enforcer': '#00e5ff', 'lifecycle-tracker': '#ffea00', 'health-monitor': '#ff4081',
            'quota-guardian': '#00bcd4', 'arch-diagram': '#69f0ae', 'costopt-intelligence': '#ffd740',
        };
        skills.forEach(s => {
            const el = document.createElement('div');
            el.className = 'skill-tag';
            const color = skillColors[s.name] || '#00b4ff';
            el.style.setProperty('--skill-color', color);
            el.textContent = `${icons[s.name] || '📎'} ${s.name}`;
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

    // New session button
    document.getElementById('btn-new-session').addEventListener('click', () => {
        Chat.clear();
        Chat.addMessage('assistant', 'New session started. How can I help with your AWS infrastructure?');
    });

    // Health check
    try {
        const health = await API.health();
        document.getElementById('status-text').textContent = `${health.skills} skills loaded`;
    } catch (e) {
        document.getElementById('status-indicator').className = 'status-dot';
        document.getElementById('status-indicator').style.background = '#ef4444';
        document.getElementById('status-text').textContent = 'Disconnected';
    }
});
