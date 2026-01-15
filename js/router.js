/**
 * Simple client-side router
 */
const Router = {
    routes: {},
    currentRoute: null,
    appElement: null,

    /**
     * Initialize router
     * @param {string} appSelector - App container selector
     */
    init(appSelector = '#app') {
        this.appElement = document.querySelector(appSelector);

        // Handle browser back/forward
        window.addEventListener('popstate', () => {
            this.navigate(window.location.hash.slice(1) || '/', false);
        });
    },

    /**
     * Register a route
     * @param {string} path
     * @param {Function} handler - Returns HTML string or element
     */
    register(path, handler) {
        this.routes[path] = handler;
    },

    /**
     * Navigate to route
     * @param {string} path
     * @param {boolean} pushState - Add to browser history
     * @param {object} data - Data to pass to route
     */
    async navigate(path, pushState = true, data = {}) {
        const handler = this.routes[path] || this.routes['/404'];

        if (!handler) {
            console.error(`No route found for: ${path}`);
            return;
        }

        if (pushState) {
            window.history.pushState(data, '', `#${path}`);
        }

        this.currentRoute = path;

        // Clear app and render new content
        this.appElement.innerHTML = '';
        this.appElement.className = 'fade-in';

        const content = await handler(data);

        if (typeof content === 'string') {
            this.appElement.innerHTML = content;
        } else if (content instanceof HTMLElement) {
            this.appElement.appendChild(content);
        }

        // Re-trigger fade animation
        void this.appElement.offsetWidth;

        // Call page init if defined
        if (window.pageInit && typeof window.pageInit === 'function') {
            window.pageInit();
            window.pageInit = null;
        }
    },

    /**
     * Start router - navigate to initial route
     */
    start() {
        const initialPath = window.location.hash.slice(1) || '/';
        this.navigate(initialPath, false);
    },

    /**
     * Get current route
     * @returns {string}
     */
    getCurrentRoute() {
        return this.currentRoute;
    }
};
