/**
 * TRACE Application
 */
const App = {
    // Store state
    state: {
        email: '',
        maskedEmail: '',
        scanToken: '',
        depth: 1,
        findings: [],
        scanTime: 0,
        riskScore: 0,
        riskLevel: 'LOW',
        auditLog: [],
    },

    /**
     * Initialize application
     */
    init() {
        Audio.init();
        Router.init('#app');
        this.registerRoutes();
        Router.start();
    },

    /**
     * Register all routes
     */
    registerRoutes() {
        Router.register('/', () => this.renderLanding());
        Router.register('/verify', (data) => this.renderVerify(data));
        Router.register('/scan', (data) => this.renderScan(data));
        Router.register('/results', (data) => this.renderResults(data));
        Router.register('/404', () => this.render404());
    },

    /**
     * Landing page
     */
    renderLanding() {
        const html = `
            <div class="page">
                <div class="terminal">
                    <div class="terminal__header">
                        <span class="terminal__dot terminal__dot--red"></span>
                        <span class="terminal__dot terminal__dot--yellow"></span>
                        <span class="terminal__dot terminal__dot--green"></span>
                        <span class="terminal__title">trace v1.0.0</span>
                    </div>
                    <div class="terminal__body">
                        <pre class="ascii-logo">${Terminal.getLogo()}</pre>

                        <p class="terminal-text" id="tagline"></p>

                        <div class="terminal-input-line">
                            <span class="terminal-input-line__prompt">&gt; ENTER SEED EMAIL:</span>
                            <input
                                type="email"
                                id="email-input"
                                class="terminal-input"
                                placeholder="you@example.com"
                                autocomplete="email"
                            >
                        </div>

                        <div id="error-message" class="status-message status-message--error hidden"></div>

                        <button id="submit-btn" class="btn btn--primary btn--block" disabled>
                            [ INITIATE TRACE ]
                        </button>

                        <div class="security-section">
                            <div class="section-header">SECURITY</div>
                            <div class="security-grid">
                                <div class="security-item">
                                    <span class="security-item__icon">■</span>
                                    <div>
                                        <div class="security-item__title">ZERO DATA RETENTION</div>
                                        <div class="security-item__desc">We store nothing. Results exist only in your browser.</div>
                                    </div>
                                </div>
                                <div class="security-item">
                                    <span class="security-item__icon">■</span>
                                    <div>
                                        <div class="security-item__title">VERIFICATION REQUIRED</div>
                                        <div class="security-item__desc">You can only scan emails you own.</div>
                                    </div>
                                </div>
                                <div class="security-item">
                                    <span class="security-item__icon">■</span>
                                    <div>
                                        <div class="security-item__title">OPEN SOURCE</div>
                                        <div class="security-item__desc">Don't trust us—verify the code yourself.</div>
                                    </div>
                                </div>
                                <div class="security-item">
                                    <span class="security-item__icon">■</span>
                                    <div>
                                        <div class="security-item__title">API PROXYING</div>
                                        <div class="security-item__desc">Your IP is never exposed to third parties.</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <footer class="footer">
                    TRACE v1.0 | For authorized self-assessment only
                </footer>
            </div>
        `;

        // Set up page initialization
        window.pageInit = () => {
            const tagline = document.getElementById('tagline');
            const emailInput = document.getElementById('email-input');
            const submitBtn = document.getElementById('submit-btn');
            const errorMsg = document.getElementById('error-message');

            // Type tagline
            Terminal.typeText(tagline, 'See how far your digital footprint goes.', 25);

            // Email validation
            const validateEmail = (email) => {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            };

            emailInput.addEventListener('input', () => {
                const valid = validateEmail(emailInput.value);
                submitBtn.disabled = !valid;
                errorMsg.classList.add('hidden');
            });

            emailInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !submitBtn.disabled) {
                    submitBtn.click();
                }
            });

            // Submit handler
            submitBtn.addEventListener('click', async () => {
                const email = emailInput.value.trim();

                submitBtn.disabled = true;
                submitBtn.innerHTML = '[ SENDING<span class="loading-dots"></span> ]';
                errorMsg.classList.add('hidden');

                try {
                    const result = await API.sendVerification(email);

                    App.state.email = email;
                    App.state.maskedEmail = result.masked_email;

                    Audio.beep();
                    Router.navigate('/verify', true, { expiresIn: result.expires_in });
                } catch (error) {
                    errorMsg.textContent = error.error || 'Failed to send verification';
                    errorMsg.classList.remove('hidden');
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '[ INITIATE TRACE ]';
                }
            });

            // Focus input
            setTimeout(() => emailInput.focus(), 500);
        };

        return html;
    },

    /**
     * Verification page
     */
    renderVerify(data) {
        const expiresIn = data.expiresIn || 300;

        const html = `
            <div class="page">
                <div class="terminal">
                    <div class="terminal__header">
                        <span class="terminal__dot terminal__dot--red"></span>
                        <span class="terminal__dot terminal__dot--yellow"></span>
                        <span class="terminal__dot terminal__dot--green"></span>
                        <span class="terminal__title">trace - verification</span>
                    </div>
                    <div class="terminal__body">
                        <pre class="ascii-logo">${Terminal.getLogo()}</pre>

                        <p class="terminal-text terminal-text--accent">&gt; VERIFICATION REQUIRED</p>

                        <hr class="terminal-divider">

                        <p class="terminal-text">Code sent to <strong>${this.state.maskedEmail}</strong></p>
                        <p class="terminal-text terminal-text--muted">
                            Expires in: <span id="countdown" class="countdown">${Terminal.formatTime(expiresIn)}</span>
                        </p>

                        <div class="code-input-wrapper" id="code-inputs">
                            <input type="text" maxlength="1" class="code-input" data-index="0" inputmode="numeric">
                            <input type="text" maxlength="1" class="code-input" data-index="1" inputmode="numeric">
                            <input type="text" maxlength="1" class="code-input" data-index="2" inputmode="numeric">
                            <input type="text" maxlength="1" class="code-input" data-index="3" inputmode="numeric">
                            <input type="text" maxlength="1" class="code-input" data-index="4" inputmode="numeric">
                            <input type="text" maxlength="1" class="code-input" data-index="5" inputmode="numeric">
                        </div>

                        <div id="error-message" class="status-message status-message--error hidden"></div>

                        <hr class="terminal-divider">

                        <p class="terminal-text terminal-text--accent">&gt; SELECT SCAN DEPTH:</p>

                        <div class="radio-group" id="depth-options">
                            <div class="radio-option radio-option--selected" data-value="1">
                                <div class="radio-option__indicator"></div>
                                <div class="radio-option__content">
                                    <div class="radio-option__label">1 HOP - Direct findings only</div>
                                    <div class="radio-option__desc">~30 seconds</div>
                                </div>
                            </div>
                            <div class="radio-option" data-value="2">
                                <div class="radio-option__indicator"></div>
                                <div class="radio-option__content">
                                    <div class="radio-option__label">2 HOPS - Discover linked accounts</div>
                                    <div class="radio-option__desc">~60 seconds</div>
                                </div>
                            </div>
                            <div class="radio-option" data-value="3">
                                <div class="radio-option__indicator"></div>
                                <div class="radio-option__content">
                                    <div class="radio-option__label">3 HOPS - Deep trace</div>
                                    <div class="radio-option__desc">~90 seconds</div>
                                </div>
                            </div>
                        </div>

                        <hr class="terminal-divider">

                        <button id="verify-btn" class="btn btn--primary btn--block" disabled>
                            [ BEGIN TRACE ]
                        </button>

                        <button id="resend-btn" class="btn btn--ghost btn--block" disabled>
                            Resend code (available in <span id="resend-countdown">60</span>s)
                        </button>
                    </div>
                </div>
            </div>
        `;

        window.pageInit = () => {
            const codeInputs = document.querySelectorAll('.code-input');
            const verifyBtn = document.getElementById('verify-btn');
            const resendBtn = document.getElementById('resend-btn');
            const errorMsg = document.getElementById('error-message');
            const countdown = document.getElementById('countdown');
            const resendCountdown = document.getElementById('resend-countdown');
            const depthOptions = document.querySelectorAll('.radio-option');

            let selectedDepth = 1;
            let cancelCountdown;

            // Start main countdown
            cancelCountdown = Terminal.startCountdown(
                countdown,
                expiresIn,
                null,
                () => {
                    errorMsg.textContent = 'Code expired. Please request a new one.';
                    errorMsg.classList.remove('hidden');
                    verifyBtn.disabled = true;
                }
            );

            // Resend countdown
            let resendRemaining = 60;
            const resendInterval = setInterval(() => {
                resendRemaining--;
                resendCountdown.textContent = resendRemaining;
                if (resendRemaining <= 0) {
                    clearInterval(resendInterval);
                    resendBtn.disabled = false;
                    resendBtn.innerHTML = '[ RESEND CODE ]';
                }
            }, 1000);

            // Code input handling
            const getCode = () => {
                return Array.from(codeInputs).map(i => i.value).join('');
            };

            const checkCode = () => {
                const code = getCode();
                verifyBtn.disabled = code.length !== 6;
            };

            codeInputs.forEach((input, index) => {
                input.addEventListener('input', (e) => {
                    const value = e.target.value.replace(/\D/g, '');
                    e.target.value = value;

                    if (value && index < 5) {
                        codeInputs[index + 1].focus();
                    }

                    Audio.beep();
                    checkCode();
                });

                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Backspace' && !e.target.value && index > 0) {
                        codeInputs[index - 1].focus();
                    }
                    if (e.key === 'Enter' && !verifyBtn.disabled) {
                        verifyBtn.click();
                    }
                });

                input.addEventListener('paste', (e) => {
                    e.preventDefault();
                    const paste = (e.clipboardData || window.clipboardData).getData('text');
                    const digits = paste.replace(/\D/g, '').slice(0, 6);

                    digits.split('').forEach((digit, i) => {
                        if (codeInputs[i]) {
                            codeInputs[i].value = digit;
                        }
                    });

                    checkCode();
                });
            });

            // Depth selection
            depthOptions.forEach(option => {
                option.addEventListener('click', () => {
                    depthOptions.forEach(o => o.classList.remove('radio-option--selected'));
                    option.classList.add('radio-option--selected');
                    selectedDepth = parseInt(option.dataset.value);
                    Audio.beep();
                });
            });

            // Verify button
            verifyBtn.addEventListener('click', async () => {
                const code = getCode();

                verifyBtn.disabled = true;
                verifyBtn.innerHTML = '[ VERIFYING<span class="loading-dots"></span> ]';
                errorMsg.classList.add('hidden');

                try {
                    const result = await API.confirmVerification(App.state.email, code);

                    App.state.scanToken = result.scan_token;
                    App.state.depth = selectedDepth;

                    if (cancelCountdown) cancelCountdown();

                    Audio.beep();
                    Router.navigate('/scan');
                } catch (error) {
                    errorMsg.textContent = error.error || 'Verification failed';
                    errorMsg.classList.remove('hidden');
                    verifyBtn.disabled = false;
                    verifyBtn.innerHTML = '[ BEGIN TRACE ]';

                    // Clear inputs
                    codeInputs.forEach(i => i.value = '');
                    codeInputs[0].focus();
                }
            });

            // Resend button
            resendBtn.addEventListener('click', async () => {
                resendBtn.disabled = true;
                resendBtn.innerHTML = '[ SENDING<span class="loading-dots"></span> ]';

                try {
                    const result = await API.sendVerification(App.state.email);

                    // Reset countdown
                    if (cancelCountdown) cancelCountdown();
                    cancelCountdown = Terminal.startCountdown(countdown, result.expires_in);

                    // Reset resend countdown
                    resendRemaining = 60;
                    resendBtn.innerHTML = `Resend code (available in <span id="resend-countdown">60</span>s)`;

                    errorMsg.classList.add('hidden');
                } catch (error) {
                    errorMsg.textContent = error.error || 'Failed to resend';
                    errorMsg.classList.remove('hidden');
                    resendBtn.disabled = false;
                    resendBtn.innerHTML = '[ RESEND CODE ]';
                }
            });

            // Focus first input
            setTimeout(() => codeInputs[0].focus(), 100);
        };

        return html;
    },

    /**
     * Scan page with graph visualization
     */
    renderScan() {
        const html = `
            <div class="scan-layout">
                <div class="scan-layout__graph">
                    <div id="graph-container" class="graph-container"></div>
                </div>

                <div class="scan-layout__sidebar">
                    <div class="scan-progress">
                        <div class="scan-progress__header">
                            <span class="scan-progress__title">&gt; SCANNING</span>
                            <span class="scan-progress__time" id="scan-time">0:00</span>
                        </div>
                        <div class="scan-progress__bar">
                            <div class="scan-progress__fill" id="progress-fill" style="width: 0%"></div>
                        </div>
                        <div class="scan-progress__stats">
                            <span>Nodes: <span id="node-count">0</span></span>
                            <span>Depth: ${this.state.depth}</span>
                        </div>
                    </div>

                    <div class="scan-log">
                        <div class="scan-log__header">&gt; AUDIT LOG</div>
                        <div class="scan-log__body" id="scan-log"></div>
                    </div>

                    <button id="abort-btn" class="btn btn--secondary btn--block">
                        [ ABORT SCAN ]
                    </button>

                    <button id="complete-btn" class="btn btn--primary btn--block hidden">
                        [ VIEW RESULTS ]
                    </button>
                </div>
            </div>
        `;

        window.pageInit = () => {
            // Initialize graph
            Graph.init('graph-container');

            // Elements
            const scanLog = document.getElementById('scan-log');
            const progressFill = document.getElementById('progress-fill');
            const nodeCount = document.getElementById('node-count');
            const scanTime = document.getElementById('scan-time');
            const abortBtn = document.getElementById('abort-btn');
            const completeBtn = document.getElementById('complete-btn');

            // State
            let startTime = Date.now();
            let isComplete = false;
            let findings = [];

            // Timer
            const timerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                scanTime.textContent = Terminal.formatTime(elapsed);
            }, 1000);

            // Add log entry
            const addLog = (message, type = 'info') => {
                const entry = document.createElement('div');
                entry.className = `scan-log__entry scan-log__entry--${type}`;

                const time = new Date().toLocaleTimeString('en-US', {
                    hour12: false,
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                });

                entry.innerHTML = `<span class="scan-log__timestamp">[${time}]</span>${message}`;
                scanLog.appendChild(entry);
                scanLog.scrollTop = scanLog.scrollHeight;
            };

            // Update progress
            const updateProgress = (percent) => {
                progressFill.style.width = `${percent}%`;
                nodeCount.textContent = Graph.getNodeCount();
            };

            // Complete scan
            const completeScan = () => {
                if (isComplete) return;
                isComplete = true;

                clearInterval(timerInterval);
                addLog('SCAN COMPLETE', 'success');
                addLog('ALL DATA CLEARED FROM SERVER MEMORY', 'info');

                updateProgress(100);
                abortBtn.classList.add('hidden');
                completeBtn.classList.remove('hidden');

                // Store findings for results page
                App.state.findings = findings;
                App.state.scanTime = (Date.now() - startTime) / 1000;
            };

            // Abort handler
            abortBtn.addEventListener('click', () => {
                if (confirm('Abort scan? Results so far will be lost.')) {
                    clearInterval(timerInterval);
                    Router.navigate('/');
                }
            });

            // Complete handler
            completeBtn.addEventListener('click', () => {
                Router.navigate('/results');
            });

            // Start scan logging
            addLog('SESSION CREATED (NO DATA STORED)', 'info');
            addLog('VERIFICATION TOKEN VALIDATED', 'success');
            addLog(`INITIATING ${this.state.depth}-HOP SCAN`, 'info');

            // Add root node (email)
            const rootFinding = {
                id: 'root-email',
                type: 'email',
                severity: 'low',
                title: this.state.maskedEmail || 'Seed Email',
                description: 'Scan seed',
                source: 'User Input',
                timestamp: new Date().toISOString(),
            };
            Graph.addNode(rootFinding);
            findings.push(rootFinding);

            // Connect to backend SSE (or simulate if backend not ready)
            this.connectToScan(addLog, updateProgress, findings, completeScan);
        };

        return html;
    },

    /**
     * Connect to real backend SSE endpoint
     */
    connectToScan(addLog, updateProgress, findings, onComplete) {
        // Check if we have a real scan token
        if (!this.state.scanToken) {
            addLog('NO SCAN TOKEN - RUNNING DEMO MODE', 'warning');
            this.runDemoScan(addLog, updateProgress, findings, onComplete);
            return;
        }

        // Try real backend
        const url = `${API.baseUrl}/scan?token=${encodeURIComponent(this.state.scanToken)}&depth=${this.state.depth}`;

        addLog('CONNECTING TO SCAN ENDPOINT...', 'info');

        let eventSource;

        try {
            eventSource = new EventSource(url);

            eventSource.addEventListener('start', (e) => {
                const data = JSON.parse(e.data);
                addLog('SCAN STARTED', 'success');
            });

            eventSource.addEventListener('finding', (e) => {
                const data = JSON.parse(e.data);
                const finding = data.finding;

                // Add to graph
                Graph.addNode(finding);
                findings.push(finding);

                // Log based on severity
                const logType = finding.severity === 'critical' ? 'error' :
                               finding.severity === 'high' ? 'warning' : 'success';
                addLog(`FOUND: ${finding.title}`, logType);
            });

            eventSource.addEventListener('progress', (e) => {
                const data = JSON.parse(e.data);
                updateProgress(data.progress);
            });

            eventSource.addEventListener('complete', (e) => {
                const data = JSON.parse(e.data);
                eventSource.close();

                // Store results
                this.state.findings = data.results.findings;
                this.state.auditLog = data.results.audit_log;
                this.state.scanTime = data.results.scan_time_seconds;
                this.state.riskScore = data.results.risk_score;
                this.state.riskLevel = data.results.risk_level;

                onComplete();
            });

            eventSource.addEventListener('error', (e) => {
                let errorData;
                try {
                    errorData = JSON.parse(e.data);
                } catch {
                    errorData = { error: 'Connection lost' };
                }

                addLog(`ERROR: ${errorData.error || 'Unknown error'}`, 'error');
                eventSource.close();

                // Fall back to demo
                addLog('FALLING BACK TO DEMO MODE', 'warning');
                this.runDemoScan(addLog, updateProgress, findings, onComplete);
            });

            eventSource.onerror = () => {
                addLog('CONNECTION ERROR - USING DEMO MODE', 'warning');
                eventSource.close();
                this.runDemoScan(addLog, updateProgress, findings, onComplete);
            };

        } catch (error) {
            addLog(`FAILED TO CONNECT: ${error.message}`, 'error');
            addLog('RUNNING DEMO MODE', 'warning');
            this.runDemoScan(addLog, updateProgress, findings, onComplete);
        }
    },

    /**
     * Run a demo scan with simulated findings
     */
    runDemoScan(addLog, updateProgress, findings, onComplete) {
        const demoFindings = [
            // Usernames
            { id: 'u1', type: 'username', severity: 'low', title: 'Username: johndoe', description: 'Extracted from email', source: 'Email Analysis', parent_id: 'root-email', link_label: 'username from', delay: 500 },
            { id: 'u2', type: 'username', severity: 'low', title: 'Username: john_doe', description: 'Extracted from email', source: 'Email Analysis', parent_id: 'root-email', link_label: 'username from', delay: 800 },

            // Breaches
            { id: 'b1', type: 'breach', severity: 'critical', title: 'Password Hash Exposed', description: 'Found in 3 data breaches', source: 'Have I Been Pwned', parent_id: 'root-email', link_label: 'exposed in', delay: 1500 },
            { id: 'b2', type: 'breach', severity: 'high', title: 'LinkedIn Breach (2021)', description: 'Potential exposure: email, name, phone', source: 'Breach Database', parent_id: 'root-email', link_label: 'potentially in', delay: 2000 },

            // Accounts from username
            { id: 'a1', type: 'account', severity: 'medium', title: 'GitHub', description: 'Account found on GitHub', source: 'GitHub', source_url: 'https://github.com/johndoe', parent_id: 'u1', link_label: 'found on', delay: 3000 },
            { id: 'a2', type: 'account', severity: 'medium', title: 'Reddit', description: 'Account found on Reddit', source: 'Reddit', source_url: 'https://reddit.com/u/johndoe', parent_id: 'u1', link_label: 'found on', delay: 3500 },
            { id: 'a3', type: 'account', severity: 'medium', title: 'Twitter/X', description: 'Account found on X', source: 'Twitter/X', source_url: 'https://x.com/johndoe', parent_id: 'u1', link_label: 'found on', delay: 4000 },
            { id: 'a4', type: 'account', severity: 'medium', title: 'LinkedIn', description: 'Account found on LinkedIn', source: 'LinkedIn', parent_id: 'u2', link_label: 'found on', delay: 4500 },

            // Personal info from GitHub
            { id: 'p1', type: 'personal_info', severity: 'high', title: 'Real Name: John Doe', description: 'Name from GitHub profile', source: 'GitHub', parent_id: 'a1', link_label: 'real name', delay: 5500 },
            { id: 'p2', type: 'personal_info', severity: 'medium', title: 'Location: San Francisco, CA', description: 'Location from GitHub profile', source: 'GitHub', parent_id: 'a1', link_label: 'located in', delay: 6000 },
            { id: 'p3', type: 'personal_info', severity: 'medium', title: 'Employer: Acme Corp', description: 'Company from GitHub profile', source: 'GitHub', parent_id: 'a1', link_label: 'works at', delay: 6500 },

            // Gravatar
            { id: 'g1', type: 'personal_info', severity: 'low', title: 'Profile Photo Found', description: 'Gravatar profile photo exists', source: 'Gravatar', parent_id: 'root-email', link_label: 'photo on', delay: 7000 },

            // Domain
            { id: 'd1', type: 'domain', severity: 'medium', title: 'Domain: johndoe.dev', description: 'Potentially associated domain (active)', source: 'DNS Lookup', parent_id: 'root-email', link_label: 'may own', delay: 8000 },

            // PGP
            { id: 'pgp1', type: 'account', severity: 'low', title: 'PGP Key (OpenPGP)', description: 'Public PGP key registered', source: 'keys.openpgp.org', parent_id: 'root-email', link_label: 'has PGP key', delay: 9000 },
        ];

        const totalDuration = 10000; // 10 seconds
        let processedCount = 0;

        demoFindings.forEach(finding => {
            setTimeout(() => {
                // Add log entry
                const logType = finding.severity === 'critical' ? 'error' :
                               finding.severity === 'high' ? 'warning' : 'success';
                addLog(`FOUND: ${finding.title}`, logType);

                // Add to graph
                Graph.addNode({
                    ...finding,
                    timestamp: new Date().toISOString(),
                });

                findings.push(finding);
                processedCount++;

                // Update progress
                const progress = Math.min(95, (finding.delay / totalDuration) * 100);
                updateProgress(progress);

            }, finding.delay);
        });

        // Complete after all findings
        setTimeout(() => {
            onComplete();
        }, totalDuration + 500);
    },

    /**
     * Results page with receipt
     */
    renderResults() {
        // Get results from state
        const results = {
            findings: this.state.findings || [],
            audit_log: this.state.auditLog || [],
            scan_time_seconds: this.state.scanTime || 0,
            total_nodes: this.state.findings?.length || 0,
            risk_score: this.state.riskScore || 0,
            risk_level: this.state.riskLevel || 'LOW',
        };

        // Calculate risk if not set
        if (!this.state.riskScore) {
            const { score, level } = this.calculateRisk(results.findings);
            results.risk_score = score;
            results.risk_level = level;
        }

        const html = `
            <div class="receipt-page">
                ${Receipt.generate(results)}
            </div>
        `;

        window.pageInit = () => {
            // PDF download button
            document.getElementById('download-pdf-btn').addEventListener('click', () => {
                Audio.beep();
                PDF.generate(results);
            });

            // New trace button
            document.getElementById('new-trace-btn').addEventListener('click', () => {
                // Clear state
                this.state = {
                    email: '',
                    maskedEmail: '',
                    scanToken: '',
                    depth: 1,
                    findings: [],
                    scanTime: 0,
                    riskScore: 0,
                    riskLevel: 'LOW',
                    auditLog: [],
                };

                Router.navigate('/');
            });
        };

        return html;
    },

    /**
     * Calculate risk score client-side
     */
    calculateRisk(findings) {
        let score = 0;

        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        findings.forEach(f => {
            const severity = (f.severity || 'low').toLowerCase();
            if (counts[severity] !== undefined) {
                counts[severity]++;
            }
        });

        // Base scoring
        score += Math.min(counts.critical * 25, 50);
        score += Math.min(counts.high * 10, 30);
        score += Math.min(counts.medium * 3, 15);
        score += Math.min(counts.low * 1, 5);

        // Check for high-risk patterns
        const allText = findings.map(f => `${f.title} ${f.description}`.toLowerCase()).join(' ');

        if (allText.includes('password') && allText.includes('exposed')) score += 15;
        if (allText.includes('phone')) score += 10;
        if (allText.includes('name:') && allText.includes('location')) score += 5;
        if (counts.medium + counts.high + counts.critical > 10) score += 5;

        score = Math.min(score, 100);

        let level = 'LOW';
        if (score >= 70) level = 'CRITICAL';
        else if (score >= 50) level = 'HIGH';
        else if (score >= 30) level = 'MEDIUM';

        return { score, level };
    },

    /**
     * 404 page
     */
    render404() {
        return `
            <div class="page">
                <div class="terminal">
                    <div class="terminal__header">
                        <span class="terminal__dot terminal__dot--red"></span>
                        <span class="terminal__dot terminal__dot--yellow"></span>
                        <span class="terminal__dot terminal__dot--green"></span>
                        <span class="terminal__title">trace - error</span>
                    </div>
                    <div class="terminal__body">
                        <pre class="ascii-logo">${Terminal.getLogo()}</pre>

                        <p class="terminal-text terminal-text--error">&gt; ERROR 404: PAGE NOT FOUND</p>

                        <hr class="terminal-divider">

                        <button onclick="Router.navigate('/')" class="btn btn--primary">
                            [ RETURN HOME ]
                        </button>
                    </div>
                </div>
            </div>
        `;
    }
};

// Start app when DOM ready
document.addEventListener('DOMContentLoaded', () => App.init());
