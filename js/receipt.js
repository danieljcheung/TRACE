/**
 * Receipt generator for TRACE results
 */
const Receipt = {
    /**
     * Generate receipt HTML from scan results
     * @param {object} results - Scan results
     * @returns {string} HTML string
     */
    generate(results) {
        const {
            findings = [],
            audit_log = [],
            scan_time_seconds = 0,
            total_nodes = 0,
            risk_score = 0,
            risk_level = 'LOW',
        } = results;

        // Group findings by severity
        const grouped = this.groupBySeverity(findings);

        // Count by severity
        const counts = {
            critical: grouped.critical.length,
            high: grouped.high.length,
            medium: grouped.medium.length,
            low: grouped.low.length,
        };

        // Get seed email (first email node)
        const seedNode = findings.find(f => f.type === 'email');
        const seedEmail = seedNode?.title || 'Unknown';

        // Generate timestamp
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

        return `
            <div class="receipt">
                <!-- Header -->
                <div class="receipt__header">
                    <pre class="receipt__logo">${this.getAsciiLogo()}</pre>
                    <div class="receipt__title">SCAN RECEIPT</div>
                    <div class="receipt__subtitle">Digital Footprint Analysis</div>
                </div>

                <!-- Meta Info -->
                <div class="receipt__meta">
                    <div class="receipt__meta-item">
                        <span class="receipt__meta-label">SEED:</span>
                        <span class="receipt__meta-value">${this.escapeHtml(seedEmail)}</span>
                    </div>
                    <div class="receipt__meta-item">
                        <span class="receipt__meta-label">TIMESTAMP:</span>
                        <span class="receipt__meta-value">${timestamp}</span>
                    </div>
                    <div class="receipt__meta-item">
                        <span class="receipt__meta-label">SCAN TIME:</span>
                        <span class="receipt__meta-value">${scan_time_seconds.toFixed(1)}s</span>
                    </div>
                    <div class="receipt__meta-item">
                        <span class="receipt__meta-label">NODES:</span>
                        <span class="receipt__meta-value">${total_nodes}</span>
                    </div>
                </div>

                <!-- Risk Score -->
                <div class="receipt__risk">
                    <div class="receipt__risk-title">EXPOSURE RISK ASSESSMENT</div>
                    <div class="receipt__risk-score receipt__risk-score--${risk_level.toLowerCase()}">${risk_score}</div>
                    <div class="receipt__risk-level receipt__risk-score--${risk_level.toLowerCase()}">${risk_level}</div>
                    <div class="receipt__risk-bar">${this.getRiskBar(risk_score)}</div>
                </div>

                <!-- Summary Stats -->
                <div class="receipt__stats">
                    <div class="receipt__stat">
                        <div class="receipt__stat-value receipt__stat-value--critical">${counts.critical}</div>
                        <div class="receipt__stat-label">Critical</div>
                    </div>
                    <div class="receipt__stat">
                        <div class="receipt__stat-value receipt__stat-value--high">${counts.high}</div>
                        <div class="receipt__stat-label">High</div>
                    </div>
                    <div class="receipt__stat">
                        <div class="receipt__stat-value receipt__stat-value--medium">${counts.medium}</div>
                        <div class="receipt__stat-label">Medium</div>
                    </div>
                    <div class="receipt__stat">
                        <div class="receipt__stat-value receipt__stat-value--low">${counts.low}</div>
                        <div class="receipt__stat-label">Low</div>
                    </div>
                </div>

                <div class="receipt__divider">═══════════════════ FINDINGS ═══════════════════</div>

                <!-- Findings -->
                <div class="receipt__findings">
                    ${this.renderFindingsSection('CRITICAL', grouped.critical, 'critical')}
                    ${this.renderFindingsSection('HIGH', grouped.high, 'high')}
                    ${this.renderFindingsSection('MEDIUM', grouped.medium, 'medium')}
                    ${this.renderFindingsSection('LOW', grouped.low, 'low')}
                </div>

                <!-- Audit Log -->
                <div class="receipt__audit">
                    <div class="receipt__audit-title">SECURITY AUDIT LOG</div>
                    <div class="receipt__audit-log">
                        ${audit_log.map(entry => `<div class="receipt__audit-entry">${this.escapeHtml(entry)}</div>`).join('')}
                    </div>
                </div>

                <!-- Security Notice -->
                <div class="receipt__security">
                    <div class="receipt__security-badge">
                        <span>■</span>
                        <span>CLIENT-SIDE GENERATED</span>
                    </div>
                    <div class="receipt__security-text">
                        This document was generated entirely in your browser.<br>
                        No scan data was stored on any server.
                    </div>
                </div>

                <!-- Footer -->
                <div class="receipt__footer">
                    <div class="receipt__footer-logo">▀█▀ █▀█ ▄▀█ █▀▀ █▀▀</div>
                    <div>trace v1.0 | github.com/yourname/trace</div>
                    <div>For authorized self-assessment only</div>
                </div>

                <!-- Actions -->
                <div class="receipt__actions">
                    <button id="download-pdf-btn" class="btn btn--primary btn--block">
                        [ DOWNLOAD PDF ]
                    </button>
                    <button id="new-trace-btn" class="btn btn--secondary btn--block">
                        [ NEW TRACE ]
                    </button>
                </div>
            </div>
        `;
    },

    /**
     * Group findings by severity
     */
    groupBySeverity(findings) {
        const groups = {
            critical: [],
            high: [],
            medium: [],
            low: [],
        };

        findings.forEach(f => {
            const severity = (f.severity || 'low').toLowerCase();
            if (groups[severity]) {
                groups[severity].push(f);
            }
        });

        return groups;
    },

    /**
     * Render a findings section
     */
    renderFindingsSection(title, findings, severity) {
        if (findings.length === 0) return '';

        const icons = {
            critical: '▲',
            high: '●',
            medium: '■',
            low: '○',
        };

        return `
            <div class="receipt__findings-section">
                <div class="receipt__findings-header">
                    <span class="receipt__findings-icon receipt__findings-icon--${severity}">${icons[severity]}</span>
                    <span class="receipt__findings-title">${title} SEVERITY</span>
                    <span class="receipt__findings-count">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>
                </div>
                ${findings.map(f => this.renderFinding(f)).join('')}
            </div>
        `;
    },

    /**
     * Render a single finding
     */
    renderFinding(finding) {
        return `
            <div class="receipt__finding">
                <div class="receipt__finding-title">${this.escapeHtml(finding.title)}</div>
                <div class="receipt__finding-source">${this.escapeHtml(finding.source)}${finding.source_url ? ` • ${this.escapeHtml(finding.source_url)}` : ''}</div>
            </div>
        `;
    },

    /**
     * Get ASCII risk bar
     */
    getRiskBar(score) {
        const width = 30;
        const filled = Math.round((score / 100) * width);
        const empty = width - filled;

        let char = '░';
        if (score >= 70) char = '█';
        else if (score >= 50) char = '▓';
        else if (score >= 30) char = '▒';

        return `[${char.repeat(filled)}${'─'.repeat(empty)}]`;
    },

    /**
     * Get ASCII logo
     */
    getAsciiLogo() {
        return `▀█▀ █▀█ ▄▀█ █▀▀ █▀▀
 █  █▀▄ █▀█ █▄▄ ██▄`;
    },

    /**
     * Escape HTML
     */
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};
