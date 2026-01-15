/**
 * Terminal effects: typing animation, cursor, etc.
 */
const Terminal = {
    defaultSpeed: 30,

    /**
     * Type text with animation
     * @param {HTMLElement} element - Target element
     * @param {string} text - Text to type
     * @param {number} speed - Ms per character
     * @returns {Promise} Resolves when complete
     */
    async typeText(element, text, speed = this.defaultSpeed) {
        element.textContent = '';

        for (let i = 0; i < text.length; i++) {
            element.textContent += text[i];

            // Play beep occasionally
            if (i % 10 === 0) {
                Audio.beep();
            }

            await this.sleep(speed);
        }
    },

    /**
     * Type multiple lines
     * @param {HTMLElement} container - Container element
     * @param {string[]} lines - Array of lines
     * @param {number} speed - Ms per character
     * @param {number} lineDelay - Ms between lines
     */
    async typeLines(container, lines, speed = this.defaultSpeed, lineDelay = 200) {
        for (const line of lines) {
            const lineEl = document.createElement('div');
            lineEl.className = 'terminal-text';
            container.appendChild(lineEl);

            await this.typeText(lineEl, line, speed);
            await this.sleep(lineDelay);
        }
    },

    /**
     * Create blinking cursor element
     * @returns {HTMLElement}
     */
    createCursor() {
        const cursor = document.createElement('span');
        cursor.className = 'typing-cursor';
        return cursor;
    },

    /**
     * Add cursor to element
     * @param {HTMLElement} element
     */
    addCursor(element) {
        const existingCursor = element.querySelector('.typing-cursor');
        if (!existingCursor) {
            element.appendChild(this.createCursor());
        }
    },

    /**
     * Remove cursor from element
     * @param {HTMLElement} element
     */
    removeCursor(element) {
        const cursor = element.querySelector('.typing-cursor');
        if (cursor) {
            cursor.remove();
        }
    },

    /**
     * Format countdown timer
     * @param {number} seconds
     * @returns {string} Formatted time (M:SS)
     */
    formatTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    },

    /**
     * Start countdown timer
     * @param {HTMLElement} element - Element to update
     * @param {number} seconds - Starting seconds
     * @param {Function} onTick - Called each second with remaining time
     * @param {Function} onComplete - Called when timer hits 0
     * @returns {Function} Cancel function
     */
    startCountdown(element, seconds, onTick, onComplete) {
        let remaining = seconds;

        const update = () => {
            element.textContent = this.formatTime(remaining);

            // Update styling based on time remaining
            element.classList.remove('countdown--warning', 'countdown--critical');
            if (remaining <= 30) {
                element.classList.add('countdown--critical');
            } else if (remaining <= 60) {
                element.classList.add('countdown--warning');
            }

            if (onTick) onTick(remaining);
        };

        update();

        const interval = setInterval(() => {
            remaining--;
            update();

            if (remaining <= 0) {
                clearInterval(interval);
                if (onComplete) onComplete();
            }
        }, 1000);

        return () => clearInterval(interval);
    },

    /**
     * Sleep utility
     * @param {number} ms
     * @returns {Promise}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    /**
     * Generate ASCII logo
     * @param {boolean} large - Use large variant
     * @returns {string}
     */
    getLogo(large = false) {
        if (large) {
            return `████████╗██████╗  █████╗  ██████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ██║   ██████╔╝███████║██║     █████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝`;
        }
        return `▀█▀ █▀█ ▄▀█ █▀▀ █▀▀
 █  █▀▄ █▀█ █▄▄ ██▄`;
    }
};
