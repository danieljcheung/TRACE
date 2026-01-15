/**
 * PDF Generator for TRACE results
 * Uses jsPDF library
 */
const PDF = {
    /**
     * Generate and download PDF from results
     * @param {object} results - Scan results
     */
    generate(results) {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({
            orientation: 'portrait',
            unit: 'mm',
            format: 'a4',
        });

        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();
        const margin = 20;
        const contentWidth = pageWidth - (margin * 2);
        let y = margin;

        // Colors
        const colors = {
            bg: '#0a0a0a',
            text: '#e0e0e0',
            accent: '#00ffff',
            muted: '#888888',
            critical: '#ff0044',
            high: '#ff8800',
            medium: '#ffff00',
            low: '#00ffff',
        };

        // Background
        doc.setFillColor(10, 10, 10);
        doc.rect(0, 0, pageWidth, pageHeight, 'F');

        // Helper functions
        const setColor = (color) => {
            const hex = colors[color] || color;
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            doc.setTextColor(r, g, b);
        };

        const addText = (text, x, fontSize = 10, color = 'text') => {
            setColor(color);
            doc.setFontSize(fontSize);
            doc.text(text, x, y);
        };

        const addLine = () => {
            setColor('muted');
            doc.setLineWidth(0.1);
            const r = parseInt(colors.muted.slice(1, 3), 16);
            const g = parseInt(colors.muted.slice(3, 5), 16);
            const b = parseInt(colors.muted.slice(5, 7), 16);
            doc.setDrawColor(r, g, b);
            doc.line(margin, y, pageWidth - margin, y);
            y += 5;
        };

        const checkPageBreak = (needed = 20) => {
            if (y + needed > pageHeight - margin) {
                doc.addPage();
                doc.setFillColor(10, 10, 10);
                doc.rect(0, 0, pageWidth, pageHeight, 'F');
                y = margin;
                return true;
            }
            return false;
        };

        // === HEADER ===
        doc.setFont('courier', 'bold');
        addText('TRACE', margin, 24, 'accent');
        y += 8;

        doc.setFont('courier', 'normal');
        addText('DIGITAL FOOTPRINT SCAN RECEIPT', margin, 10, 'muted');
        y += 10;

        addLine();

        // === META INFO ===
        const seedNode = results.findings?.find(f => f.type === 'email');
        const seedEmail = seedNode?.title || 'Unknown';
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

        addText(`SEED: ${seedEmail}`, margin, 9, 'text');
        y += 5;
        addText(`TIMESTAMP: ${timestamp}`, margin, 9, 'text');
        y += 5;
        addText(`SCAN TIME: ${(results.scan_time_seconds || 0).toFixed(1)}s`, margin, 9, 'text');
        y += 5;
        addText(`TOTAL NODES: ${results.total_nodes || 0}`, margin, 9, 'text');
        y += 8;

        addLine();

        // === RISK SCORE ===
        const riskLevel = (results.risk_level || 'LOW').toLowerCase();
        const riskColor = colors[riskLevel] || colors.low;

        addText('EXPOSURE RISK ASSESSMENT', margin, 10, 'muted');
        y += 10;

        setColor(riskColor);
        doc.setFontSize(36);
        doc.setFont('courier', 'bold');
        doc.text(String(results.risk_score || 0), pageWidth / 2, y, { align: 'center' });
        y += 12;

        doc.setFontSize(14);
        doc.text((results.risk_level || 'LOW').toUpperCase(), pageWidth / 2, y, { align: 'center' });
        y += 8;

        // Risk bar
        doc.setFont('courier', 'normal');
        const barWidth = 60;
        const barX = (pageWidth - barWidth) / 2;
        const filled = Math.round((results.risk_score / 100) * barWidth);

        setColor('muted');
        doc.setFontSize(8);
        const bar = '[' + '█'.repeat(Math.round(filled / 2)) + '─'.repeat(Math.round((barWidth - filled) / 2)) + ']';
        doc.text(bar, pageWidth / 2, y, { align: 'center' });
        y += 10;

        addLine();

        // === SUMMARY STATS ===
        const grouped = this.groupBySeverity(results.findings || []);
        const counts = {
            critical: grouped.critical.length,
            high: grouped.high.length,
            medium: grouped.medium.length,
            low: grouped.low.length,
        };

        addText('FINDINGS SUMMARY', margin, 10, 'muted');
        y += 8;

        const statWidth = contentWidth / 4;
        const stats = [
            { label: 'CRITICAL', value: counts.critical, color: 'critical' },
            { label: 'HIGH', value: counts.high, color: 'high' },
            { label: 'MEDIUM', value: counts.medium, color: 'medium' },
            { label: 'LOW', value: counts.low, color: 'low' },
        ];

        stats.forEach((stat, i) => {
            const x = margin + (statWidth * i) + (statWidth / 2);

            setColor(stat.color);
            doc.setFontSize(16);
            doc.setFont('courier', 'bold');
            doc.text(String(stat.value), x, y, { align: 'center' });

            setColor('muted');
            doc.setFontSize(7);
            doc.setFont('courier', 'normal');
            doc.text(stat.label, x, y + 5, { align: 'center' });
        });

        y += 15;
        addLine();

        // === FINDINGS ===
        const severities = ['critical', 'high', 'medium', 'low'];
        const severityLabels = {
            critical: 'CRITICAL SEVERITY',
            high: 'HIGH SEVERITY',
            medium: 'MEDIUM SEVERITY',
            low: 'LOW SEVERITY',
        };

        for (const severity of severities) {
            const findings = grouped[severity];
            if (findings.length === 0) continue;

            checkPageBreak(30);

            // Section header
            setColor(severity);
            doc.setFontSize(10);
            doc.setFont('courier', 'bold');
            doc.text(`▶ ${severityLabels[severity]} (${findings.length})`, margin, y);
            y += 6;

            doc.setFont('courier', 'normal');

            for (const finding of findings) {
                checkPageBreak(12);

                setColor('text');
                doc.setFontSize(9);

                // Truncate long titles
                let title = finding.title || '';
                if (title.length > 60) {
                    title = title.substring(0, 57) + '...';
                }
                doc.text(`• ${title}`, margin + 3, y);
                y += 4;

                setColor('muted');
                doc.setFontSize(7);
                doc.text(`  ${finding.source || 'Unknown source'}`, margin + 3, y);
                y += 5;
            }

            y += 3;
        }

        // === SECURITY NOTICE ===
        checkPageBreak(25);
        addLine();

        setColor('accent');
        doc.setFontSize(8);
        doc.setFont('courier', 'bold');
        doc.text('■ CLIENT-SIDE GENERATED', pageWidth / 2, y, { align: 'center' });
        y += 5;

        setColor('muted');
        doc.setFontSize(7);
        doc.setFont('courier', 'normal');
        doc.text('This document was generated entirely in your browser.', pageWidth / 2, y, { align: 'center' });
        y += 4;
        doc.text('No scan data was stored on any server.', pageWidth / 2, y, { align: 'center' });
        y += 8;

        // === FOOTER ===
        addLine();

        setColor('accent');
        doc.setFontSize(8);
        doc.text('TRACE v1.0', pageWidth / 2, y, { align: 'center' });
        y += 4;

        setColor('muted');
        doc.setFontSize(7);
        doc.text('github.com/yourname/trace', pageWidth / 2, y, { align: 'center' });
        y += 3;
        doc.text('For authorized self-assessment only', pageWidth / 2, y, { align: 'center' });

        // Save
        const filename = `trace-scan-${new Date().toISOString().slice(0, 10)}.pdf`;
        doc.save(filename);
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
    }
};
