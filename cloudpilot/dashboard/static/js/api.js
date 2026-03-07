/**
 * CloudPilot API Client
 */
const API = {
    baseUrl: '',

    async _fetch(path, options = {}) {
        const resp = await fetch(`${this.baseUrl}${path}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return resp.json();
    },

    chat(message, sessionId) {
        return this._fetch('/api/chat', {
            method: 'POST',
            body: JSON.stringify({ message, session_id: sessionId }),
        });
    },

    listSkills() {
        return this._fetch('/api/skills');
    },

    scan(skillName, regions) {
        return this._fetch(`/api/scan/${skillName}`, {
            method: 'POST',
            body: JSON.stringify({ regions }),
        });
    },

    scanAll(regions) {
        return this._fetch('/api/scan-all', {
            method: 'POST',
            body: JSON.stringify({ regions }),
        });
    },

    discover(regions) {
        return this._fetch('/api/discover', {
            method: 'POST',
            body: JSON.stringify({ regions }),
        });
    },

    diagram(viewType, resources) {
        return this._fetch('/api/diagram', {
            method: 'POST',
            body: JSON.stringify({ view_type: viewType, resources }),
        });
    },

    generateIaC(format, scope, resources) {
        return this._fetch('/api/iac', {
            method: 'POST',
            body: JSON.stringify({ format, scope, resources }),
        });
    },

    remediate(finding) {
        return this._fetch('/api/remediate', {
            method: 'POST',
            body: JSON.stringify({ finding }),
        });
    },

    getJob(jobId) {
        return this._fetch(`/api/jobs/${jobId}`);
    },

    getJobResults(jobId) {
        return this._fetch(`/api/jobs/${jobId}/results`);
    },

    health() {
        return this._fetch('/api/health');
    },
};
