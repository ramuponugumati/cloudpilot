/**
 * CloudPilot Chat UI — handles message rendering, Mermaid diagrams, code highlighting
 */
const Chat = {
    messagesEl: null,
    inputEl: null,
    sendBtn: null,
    sendIcon: null,
    sendSpinner: null,
    isLoading: false,
    mermaidCounter: 0,

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
        // Auto-resize textarea
        this.inputEl.addEventListener('input', () => {
            this.inputEl.style.height = 'auto';
            this.inputEl.style.height = Math.min(this.inputEl.scrollHeight, 120) + 'px';
        });

        mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'loose' });
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
        // Render any mermaid diagrams and highlight code
        this.postRender(contentDiv);
    },

    renderContent(text) {
        if (!text) return '';
        // Process code blocks first
        let html = text;

        // Mermaid blocks: ```mermaid ... ```
        html = html.replace(/```mermaid\n([\s\S]*?)```/g, (_, code) => {
            const id = `mermaid-${++this.mermaidCounter}`;
            return `<div class="mermaid-container" id="${id}">${this.escapeHtml(code.trim())}</div>`;
        });

        // Code blocks with language: ```lang ... ```
        html = html.replace(/```(\w+)\n([\s\S]*?)```/g, (_, lang, code) => {
            return `<div class="code-block-wrapper">` +
                `<button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button>` +
                `<pre><code class="language-${lang}">${this.escapeHtml(code.trim())}</code></pre></div>`;
        });

        // Generic code blocks: ``` ... ```
        html = html.replace(/```\n?([\s\S]*?)```/g, (_, code) => {
            return `<div class="code-block-wrapper">` +
                `<button class="copy-btn" onclick="Chat.copyCode(this)">Copy</button>` +
                `<pre><code>${this.escapeHtml(code.trim())}</code></pre></div>`;
        });

        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

        // Bold
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

        // Italic
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

        // Line breaks → paragraphs
        html = html.split('\n\n').map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');

        // Bullet lists
        html = html.replace(/<p>[-•]\s/g, '<li>').replace(/<\/p>(\s*<li>)/g, '</li>$1');

        return html;
    },

    postRender(container) {
        // Render mermaid diagrams
        container.querySelectorAll('.mermaid-container').forEach(async (el) => {
            try {
                const code = el.textContent;
                const { svg } = await mermaid.render(el.id + '-svg', code);
                el.innerHTML = svg;
            } catch (e) {
                el.innerHTML = `<pre style="color:#ef4444">Diagram render error: ${e.message}</pre>`;
            }
        });
        // Highlight code blocks
        container.querySelectorAll('pre code').forEach((el) => {
            hljs.highlightElement(el);
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
