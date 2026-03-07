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
            this.addMessage('assistant', data.response);
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

        // Mermaid blocks
        html = html.replace(/```mermaid\n([\s\S]*?)```/g, (_, code) => {
            const id = `mermaid-${++this.mermaidCounter}`;
            return `<div class="mermaid-container" id="${id}">${this.escapeHtml(code.trim())}</div>`;
        });

        // Code blocks with language
        html = html.replace(/```(\w+)\n([\s\S]*?)```/g, (_, lang, code) => {
            return `<div class="code-block-wrapper">` +
                `<button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button>` +
                `<pre><code class="language-${lang}">${this.escapeHtml(code.trim())}</code></pre></div>`;
        });

        // Generic code blocks
        html = html.replace(/```\n?([\s\S]*?)```/g, (_, code) => {
            return `<div class="code-block-wrapper">` +
                `<button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button>` +
                `<pre><code>${this.escapeHtml(code.trim())}</code></pre></div>`;
        });

        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        html = html.split('\n\n').map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
        html = html.replace(/<p>[-•]\s/g, '<li>').replace(/<\/p>(\s*<li>)/g, '</li>$1');

        return html;
    },

    _buildCostChartHTML(data) {
        const id = ++this.chartCounter;
        const colors = ['#00b4ff', '#7c4dff', '#00e676', '#ff9100', '#e040fb'];

        // Stat cards
        let statsHtml = `<div class="cost-stats-row">`;
        statsHtml += `<div class="cost-stat-card" style="--accent:#00b4ff">
            <div class="stat-icon">💰</div>
            <div class="stat-body"><div class="stat-value">$${data.total_sum.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
            <div class="stat-label">${data.num_months}-Month Total</div></div></div>`;
        statsHtml += `<div class="cost-stat-card" style="--accent:#7c4dff">
            <div class="stat-icon">📊</div>
            <div class="stat-body"><div class="stat-value">$${data.total_avg.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}</div>
            <div class="stat-label">Monthly Average</div></div></div>`;
        statsHtml += `<div class="cost-stat-card" style="--accent:#00e676">
            <div class="stat-icon">🏆</div>
            <div class="stat-body"><div class="stat-value">${data.top5[0]?.name || '-'}</div>
            <div class="stat-label">Top Service</div></div></div>`;
        statsHtml += `<div class="cost-stat-card" style="--accent:#ff9100">
            <div class="stat-icon">📈</div>
            <div class="stat-body"><div class="stat-value">${data.top5.length}</div>
            <div class="stat-label">Top Services</div></div></div>`;
        statsHtml += `</div>`;

        // Store data for Chart.js rendering in postRender
        const chartDataAttr = this.escapeHtml(JSON.stringify(data));

        return `<div class="cost-dashboard">
            ${statsHtml}
            <div class="cost-charts-row">
                <div class="cost-chart-card dark">
                    <div class="chart-header"><span class="chart-label">OVERVIEW</span><span class="chart-title">Monthly Spend Trend</span></div>
                    <canvas id="cost-line-${id}" class="cost-canvas" data-chart='${chartDataAttr}' data-type="line"></canvas>
                </div>
                <div class="cost-chart-card light">
                    <div class="chart-header"><span class="chart-label">BREAKDOWN</span><span class="chart-title">Top Services</span></div>
                    <canvas id="cost-bar-${id}" class="cost-canvas" data-chart='${chartDataAttr}' data-type="bar"></canvas>
                </div>
            </div>
        </div>`;
    },

    postRender(container) {
        // Render mermaid diagrams
        container.querySelectorAll('.mermaid-container').forEach(async (el) => {
            try {
                const code = el.textContent;
                const { svg } = await mermaid.render(el.id + '-svg', code);
                el.innerHTML = svg;
            } catch (e) {
                el.innerHTML = `<pre style="color:#ff5252">Diagram error: ${e.message}</pre>`;
            }
        });
        // Highlight code blocks
        container.querySelectorAll('pre code').forEach((el) => {
            if (typeof hljs !== 'undefined') hljs.highlightElement(el);
        });

        // Render Chart.js cost charts
        container.querySelectorAll('.cost-canvas').forEach((canvas) => {
            try {
                const data = JSON.parse(canvas.dataset.chart);
                const type = canvas.dataset.type;
                if (type === 'line') this._renderLineChart(canvas, data);
                else if (type === 'bar') this._renderBarChart(canvas, data);
            } catch (e) { console.error('Chart render error:', e); }
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
