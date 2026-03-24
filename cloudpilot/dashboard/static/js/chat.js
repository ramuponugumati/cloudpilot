/**
 * CloudPilot Chat UI — message rendering, Mermaid diagrams, code highlighting, Chart.js cost charts
 */
const Chat = {
    messagesEl: null,
    inputEl: null,
    sendBtn: null,
    sendIcon: null,
    sendSpinner: null,
    isLoading: false,
    mermaidCounter: 0,
    chartCounter: 0,

    init() {
        this.messagesEl = document.getElementById('chat-messages');
        this.inputEl = document.getElementById('chat-input');
        this.sendBtn = document.getElementById('btn-send');
        this.sendIcon = document.getElementById('send-icon');
        this.sendSpinner = document.getElementById('send-spinner');

        this.sendBtn.addEventListener('click', () => this.send());
        this.inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.send();
            }
        });
        this.inputEl.addEventListener('input', () => {
            this.inputEl.style.height = 'auto';
            this.inputEl.style.height = Math.min(this.inputEl.scrollHeight, 120) + 'px';
        });

        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    },

    async send() {
        const message = this.inputEl.value.trim();
        if (!message || this.isLoading) return;
        this.addMessage('user', message);
        this.inputEl.value = '';
        this.inputEl.style.height = 'auto';
        this.setLoading(true);
        this.addTypingIndicator();
        try {
            const data = await API.chat(message);
            this.removeTypingIndicator();
            // Render cost charts FIRST with heading, then text summary below
            if (data.chart_data && data.chart_data.type === 'cost_overview') {
                console.log('Rendering cost charts:', data.chart_data);
                this._addCostCharts(data.chart_data);
            }
            this.addMessage('assistant', data.response);
            // Render remediation action buttons if findings are available
            if (data.remediable_findings && data.remediable_findings.length > 0) {
                this._addRemediationCards(data.remediable_findings);
            }
        } catch (err) {
            this.removeTypingIndicator();
            this.addMessage('assistant', `⚠️ Error: ${err.message}`);
        } finally {
            this.setLoading(false);
        }
    },

    sendQuickAction(message) {
        this.inputEl.value = message;
        this.send();
    },

    addMessage(role, content) {
        const div = document.createElement('div');
        div.className = `message ${role}`;
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.innerHTML = this.renderContent(content);
        div.appendChild(contentDiv);
        this.messagesEl.appendChild(div);
        this.scrollToBottom();
        this.postRender(contentDiv);
    },

    renderContent(text) {
        if (!text) return '';
        let html = text;

        // Extract and render cost chart data before other processing
        html = html.replace(/<!-- COST_CHART:([\s\S]*?) -->/g, (_, jsonStr) => {
            try {
                const data = JSON.parse(jsonStr);
                return this._buildCostChartHTML(data);
            } catch (e) { return ''; }
        });

        // Extract mermaid and code blocks FIRST, replace with placeholders
        const blocks = [];
        html = html.replace(/```mermaid\n([\s\S]*?)```/g, (_, code) => {
            const id = `mermaid-${++this.mermaidCounter}`;
            const idx = blocks.length;
            blocks.push(`<div class="mermaid-container" id="${id}"><pre class="mermaid-src">${this.escapeHtml(code.trim())}</pre></div>`);
            return `%%BLOCK_${idx}%%`;
        });

        html = html.replace(/```(\w+)\n([\s\S]*?)```/g, (_, lang, code) => {
            const idx = blocks.length;
            blocks.push(`<div class="code-block-wrapper"><button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button><pre><code class="language-${lang}">${this.escapeHtml(code.trim())}</code></pre></div>`);
            return `%%BLOCK_${idx}%%`;
        });

        html = html.replace(/```\n?([\s\S]*?)```/g, (_, code) => {
            const idx = blocks.length;
            blocks.push(`<div class="code-block-wrapper"><button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button><pre><code>${this.escapeHtml(code.trim())}</code></pre></div>`);
            return `%%BLOCK_${idx}%%`;
        });

        // Now process text formatting (won't touch block placeholders)
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        html = html.split('\n\n').map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
        html = html.replace(/<p>[-•]\s/g, '<li>').replace(/<\/p>(\s*<li>)/g, '</li>$1');

        // Restore blocks
        for (let i = 0; i < blocks.length; i++) {
            html = html.replace(`%%BLOCK_${i}%%`, blocks[i]);
            // Also handle if wrapped in <p> tags
            html = html.replace(`<p>%%BLOCK_${i}%%</p>`, blocks[i]);
        }

        return html;
    },

    _buildCostChartHTML(data) {
        // Not used — charts rendered via _addCostCharts from API response
        return '';
    },

    _addCostCharts(data) {
        const id = ++this.chartCounter;
        const div = document.createElement('div');
        div.className = 'message assistant';
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content cost-message';

        let html = `<div class="cost-dashboard">`;
        html += `<h3 style="color:#e8eeff;margin:0 0 16px 0;font-size:1.2em;display:flex;align-items:center;gap:8px">
            <span style="font-size:1.4em">📊</span> Cost Analysis — ${data.num_months}-Month Overview</h3>`;
        html += `<div class="cost-stats-row">`;
        html += `<div class="cost-stat-card" style="--accent:#00b4ff">
            <div class="stat-icon">💰</div>
            <div class="stat-body"><div class="stat-value">$${data.total_sum.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
            <div class="stat-label">${data.num_months}-Month Total</div></div></div>`;
        html += `<div class="cost-stat-card" style="--accent:#7c4dff">
            <div class="stat-icon">📊</div>
            <div class="stat-body"><div class="stat-value">$${data.total_avg.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
            <div class="stat-label">Monthly Average</div></div></div>`;
        html += `<div class="cost-stat-card" style="--accent:#00e676">
            <div class="stat-icon">🏆</div>
            <div class="stat-body"><div class="stat-value">${data.top5[0]?.name || '-'}</div>
            <div class="stat-label">Top Service</div></div></div>`;
        html += `<div class="cost-stat-card" style="--accent:#ff9100">
            <div class="stat-icon">📈</div>
            <div class="stat-body"><div class="stat-value">${data.top5.length}</div>
            <div class="stat-label">Top Services</div></div></div>`;
        html += `</div>`;

        html += `<div class="cost-charts-row">
            <div class="cost-chart-card dark">
                <div class="chart-header"><span class="chart-label">OVERVIEW</span><span class="chart-title">Monthly Spend Trend</span></div>
                <canvas id="cost-line-${id}" class="cost-canvas"></canvas>
            </div>
            <div class="cost-chart-card light">
                <div class="chart-header"><span class="chart-label">BREAKDOWN</span><span class="chart-title">Top Services</span></div>
                <canvas id="cost-bar-${id}" class="cost-canvas"></canvas>
            </div>
        </div></div>`;

        contentDiv.innerHTML = html;
        div.appendChild(contentDiv);
        this.messagesEl.appendChild(div);
        this.scrollToBottom();

        requestAnimationFrame(() => {
            const lineCanvas = document.getElementById(`cost-line-${id}`);
            const barCanvas = document.getElementById(`cost-bar-${id}`);
            try {
                if (lineCanvas && typeof Chart !== 'undefined') this._renderLineChart(lineCanvas, data);
                if (barCanvas && typeof Chart !== 'undefined') this._renderBarChart(barCanvas, data);
            } catch (e) {
                console.error('Chart render error:', e);
            }
        });
    },

    postRender(container) {
        // Render mermaid diagrams
        container.querySelectorAll('.mermaid-container').forEach(async (el) => {
            try {
                const pre = el.querySelector('.mermaid-src');
                const code = pre ? pre.textContent : el.textContent;
                if (pre) pre.remove();
                const { svg } = await mermaid.render(el.id + '-svg', code);
                el.innerHTML = svg;
            } catch (e) {
                el.innerHTML = `<pre style="color:#ff5252;display:block">Diagram error: ${e.message}</pre>`;
            }
        });
        // Highlight code blocks
        container.querySelectorAll('pre code').forEach((el) => {
            if (typeof hljs !== 'undefined') hljs.highlightElement(el);
        });
    },

    _renderLineChart(canvas, data) {
        const gradient = canvas.getContext('2d').createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(0,180,255,0.3)');
        gradient.addColorStop(1, 'rgba(0,180,255,0.01)');

        new Chart(canvas, {
            type: 'line',
            data: {
                labels: data.months,
                datasets: [{
                    label: 'Total Spend',
                    data: data.monthly_totals,
                    borderColor: '#00b4ff',
                    backgroundColor: gradient,
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00b4ff',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(10,14,39,0.9)',
                        titleColor: '#e8eeff',
                        bodyColor: '#c4ccee',
                        borderColor: 'rgba(0,180,255,0.3)',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: (ctx) => `$${ctx.parsed.y.toLocaleString(undefined,{minimumFractionDigits:2})}`,
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: 'rgba(255,255,255,0.6)', font: { size: 11 } },
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: {
                            color: 'rgba(255,255,255,0.6)', font: { size: 11 },
                            callback: (v) => '$' + (v >= 1000 ? (v/1000).toFixed(1) + 'k' : v),
                        },
                    }
                }
            }
        });
    },

    _renderBarChart(canvas, data) {
        const colors = ['#00b4ff', '#7c4dff', '#00e676', '#ff9100', '#e040fb'];
        const datasets = data.top5.map((svc, i) => ({
            label: svc.name,
            data: svc.monthly,
            backgroundColor: colors[i % colors.length],
            borderRadius: 4,
            borderSkipped: false,
        }));

        new Chart(canvas, {
            type: 'bar',
            data: { labels: data.months, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#5c6478', font: { size: 11 }, padding: 12, usePointStyle: true, pointStyle: 'rectRounded' },
                    },
                    tooltip: {
                        backgroundColor: 'rgba(255,255,255,0.95)',
                        titleColor: '#1e2330',
                        bodyColor: '#5c6478',
                        borderColor: '#e2e5f0',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: (ctx) => `${ctx.dataset.label}: $${ctx.parsed.y.toLocaleString(undefined,{minimumFractionDigits:2})}`,
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#5c6478', font: { size: 11 } },
                    },
                    y: {
                        grid: { color: '#e2e5f0' },
                        ticks: {
                            color: '#5c6478', font: { size: 11 },
                            callback: (v) => '$' + (v >= 1000 ? (v/1000).toFixed(1) + 'k' : v),
                        },
                    }
                }
            }
        });
    },

    _addRemediationCards(findings) {
        const div = document.createElement('div');
        div.className = 'message assistant';
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';

        const sevColors = {critical:'#ff1744',high:'#ff9100',medium:'#ffd600',low:'#448aff',info:'#90a4ae'};
        const actionConfig = {
            'Unattached EBS': { icon: '💾', label: 'Delete Volume', color: '#ff5252' },
            'Unused EIP': { icon: '🌐', label: 'Release IP', color: '#ff9100' },
            'Unused NAT GW': { icon: '🚪', label: 'Delete NAT', color: '#ff5252' },
            'Idle EC2': { icon: '🖥️', label: 'Stop Instance', color: '#ffd600' },
            'Idle RDS': { icon: '🗄️', label: 'Stop DB', color: '#ffd600' },
            'Open port': { icon: '🔒', label: 'Restrict Access', color: '#7c4dff' },
            'Public S3': { icon: '📦', label: 'Block Public', color: '#7c4dff' },
            'Old access key': { icon: '🔑', label: 'Deactivate Key', color: '#7c4dff' },
            'Single-AZ RDS': { icon: '🛡️', label: 'Enable Multi-AZ', color: '#00b4ff' },
            'No backups': { icon: '💾', label: 'Enable Backups', color: '#00b4ff' },
            'No VPC Flow': { icon: '📡', label: 'Enable Logs', color: '#00b4ff' },
            'Untagged': { icon: '🏷️', label: 'Apply Tags', color: '#00e676' },
            'Deprecated runtime': { icon: '⬆️', label: 'Upgrade', color: '#ff9100' },
            'EOL RDS': { icon: '⬆️', label: 'Upgrade Engine', color: '#ff9100' },
        };

        function getAction(title) {
            for (const [prefix, cfg] of Object.entries(actionConfig)) {
                if (title.startsWith(prefix) || title.includes(prefix)) return cfg;
            }
            return { icon: '🔧', label: 'Fix', color: '#90a4ae' };
        }

        let html = '<div class="remediation-cards">';
        for (let i = 0; i < findings.length; i++) {
            const f = findings[i];
            const color = sevColors[f.severity] || '#90a4ae';
            const act = getAction(f.title);
            const impact = f.monthly_impact ? `$${f.monthly_impact.toLocaleString(undefined,{minimumFractionDigits:2})}/mo` : '';
            html += `<div class="remediation-card" style="border-left:3px solid ${color}">
                <div class="rem-icon">${act.icon}</div>
                <div class="rem-info">
                    <span class="rem-title">${this.escapeHtml(f.title)}</span>
                    <span class="rem-meta">${f.region}${impact ? ' · ' + impact : ''}</span>
                </div>
                <button class="rem-btn" style="background:${act.color}22;color:${act.color};border-color:${act.color}44" data-idx="${i}" onclick="Chat._executeRemediation(${i})">${act.label}</button>
            </div>`;
        }
        html += '</div>';

        // Follow-up prompt — context-aware based on skill type
        const skills = [...new Set(findings.map(f => f.skill))];
        const totalImpact = findings.reduce((s, f) => s + (f.monthly_impact || 0), 0);
        const impactStr = totalImpact > 0 ? ` (saving ~$${totalImpact.toLocaleString(undefined,{minimumFractionDigits:2})}/mo)` : '';

        const promptMap = {
            'zombie-hunter': `Would you like to clean up these unused resources? Click individual buttons or type <strong>"delete all"</strong> to remove everything${impactStr}.`,
            'security-posture': `Would you like to harden your security posture? Click individual buttons to restrict access, deactivate old keys, or block public exposure.`,
            'resiliency-gaps': `Would you like to improve resilience? Click individual buttons to enable Multi-AZ, backups, or flow logs.`,
            'tag-enforcer': `Would you like to enforce tagging? Click individual buttons to apply mandatory tags to untagged resources.`,
            'capacity-planner': `Would you like to optimize capacity? Click individual buttons to cancel underutilized reservations${impactStr}.`,
            'lifecycle-tracker': `Would you like to upgrade deprecated resources? Click individual buttons to update runtimes and engines.`,
            'costopt-intelligence': `Would you like to optimize costs? Click individual buttons to right-size or migrate resources${impactStr}.`,
        };

        let prompt = '';
        if (skills.length === 1 && promptMap[skills[0]]) {
            prompt = promptMap[skills[0]];
        } else {
            prompt = `Would you like to remediate these findings? Click individual buttons above, or type <strong>"fix all"</strong> to apply all fixes${impactStr}.`;
        }

        html += `<div class="rem-followup"><span>${prompt}</span></div>`;

        contentDiv.innerHTML = html;
        div.appendChild(contentDiv);
        this.messagesEl.appendChild(div);
        this.scrollToBottom();

        // Store findings for remediation execution
        this._pendingRemediations = findings;
    },

    async _executeRemediation(idx) {
        const finding = this._pendingRemediations && this._pendingRemediations[idx];
        if (!finding) return;

        const btn = document.querySelector(`.rem-btn[data-idx="${idx}"]`);
        if (!btn || btn.disabled) return;

        // Confirm before executing
        const ok = confirm(`Are you sure you want to remediate?\n\n${finding.title}\nResource: ${finding.resource_id}\nRegion: ${finding.region}\n\nThis action will modify your AWS resources.`);
        if (!ok) return;

        btn.disabled = true;
        btn.textContent = '⏳ Working...';
        btn.style.opacity = '0.6';

        try {
            const result = await API.remediate(finding);
            if (result.success) {
                btn.textContent = '✅ Done';
                btn.style.background = 'rgba(0,230,118,0.2)';
                btn.style.color = '#00e676';
                this.addMessage('assistant', `✅ Remediation successful: **${result.action}** on \`${finding.resource_id}\` — ${result.message}`);
            } else {
                btn.textContent = '❌ Failed';
                btn.style.background = 'rgba(255,23,68,0.2)';
                btn.style.color = '#ff1744';
                this.addMessage('assistant', `❌ Remediation failed: ${result.message}`);
            }
        } catch (err) {
            btn.textContent = '❌ Error';
            btn.style.background = 'rgba(255,23,68,0.2)';
            this.addMessage('assistant', `⚠️ Remediation error: ${err.message}`);
        }
    },

    copyCode(btn) {
        const code = btn.nextElementSibling.textContent;
        navigator.clipboard.writeText(code).then(() => {
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        });
    },

    addTypingIndicator() {
        const div = document.createElement('div');
        div.className = 'message assistant';
        div.id = 'typing-indicator';
        div.innerHTML = '<div class="message-content"><div class="typing-indicator"><span></span><span></span><span></span></div></div>';
        this.messagesEl.appendChild(div);
        this.scrollToBottom();
    },

    removeTypingIndicator() {
        const el = document.getElementById('typing-indicator');
        if (el) el.remove();
    },

    setLoading(loading) {
        this.isLoading = loading;
        this.sendBtn.disabled = loading;
        this.sendIcon.classList.toggle('hidden', loading);
        this.sendSpinner.classList.toggle('hidden', !loading);
    },

    scrollToBottom() {
        this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    clear() {
        this.messagesEl.innerHTML = '';
    },
};
