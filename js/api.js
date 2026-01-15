/**
 * API client for TRACE backend
 */
const API = {
    baseUrl: 'http://localhost:8000/api',

    /**
     * Set base URL
     * @param {string} url
     */
    setBaseUrl(url) {
        this.baseUrl = url.replace(/\/$/, '');
    },

    /**
     * Make API request
     * @param {string} endpoint
     * @param {object} options
     * @returns {Promise<object>}
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;

        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
            ...options,
        };

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw {
                    status: response.status,
                    ...data,
                };
            }

            return data;
        } catch (error) {
            if (error.status) {
                throw error;
            }
            throw {
                success: false,
                error: 'Network error. Is the backend running?',
            };
        }
    },

    /**
     * Health check
     * @returns {Promise<object>}
     */
    async health() {
        return this.request('/health');
    },

    /**
     * Send verification code
     * @param {string} email
     * @returns {Promise<object>}
     */
    async sendVerification(email) {
        return this.request('/verify/send', {
            method: 'POST',
            body: { email },
        });
    },

    /**
     * Confirm verification code
     * @param {string} email
     * @param {string} code
     * @returns {Promise<object>}
     */
    async confirmVerification(email, code) {
        return this.request('/verify/confirm', {
            method: 'POST',
            body: { email, code },
        });
    },

    /**
     * Start scan via SSE
     * @param {string} scanToken
     * @param {number} depth
     * @param {function} onFinding - Called for each finding
     * @param {function} onComplete - Called when scan completes
     * @param {function} onError - Called on error
     * @returns {function} Abort function
     */
    startScan(scanToken, depth, onFinding, onComplete, onError) {
        const url = `${this.baseUrl}/scan?token=${encodeURIComponent(scanToken)}&depth=${depth}`;

        let eventSource;

        try {
            eventSource = new EventSource(url);

            eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    if (data.type === 'finding') {
                        onFinding(data.finding);
                    } else if (data.type === 'complete') {
                        eventSource.close();
                        onComplete(data);
                    } else if (data.type === 'log') {
                        // Optional: handle log messages
                    }
                } catch (e) {
                    console.error('Failed to parse SSE message:', e);
                }
            };

            eventSource.onerror = (error) => {
                eventSource.close();
                onError(error);
            };

        } catch (error) {
            onError(error);
        }

        // Return abort function
        return () => {
            if (eventSource) {
                eventSource.close();
            }
        };
    }
};

// Auto-detect backend URL
(function() {
    // If running on localhost, use localhost backend
    // Otherwise, use relative path (for production)
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        API.baseUrl = 'http://localhost:8000/api';
    } else {
        // Production - assume backend is on same domain
        API.baseUrl = '/api';
    }
})();
