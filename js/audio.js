/**
 * Audio manager for terminal sounds
 */
const Audio = {
    beepSound: null,
    enabled: true,
    volume: 0.3,

    init() {
        this.beepSound = document.getElementById('beep-sound');
        if (this.beepSound) {
            this.beepSound.volume = this.volume;
        }
    },

    beep() {
        if (!this.enabled || !this.beepSound) return;

        // Clone to allow overlapping sounds
        const sound = this.beepSound.cloneNode();
        sound.volume = this.volume;
        sound.play().catch(() => {}); // Ignore autoplay restrictions
    },

    setEnabled(enabled) {
        this.enabled = enabled;
    },

    setVolume(vol) {
        this.volume = Math.max(0, Math.min(1, vol));
        if (this.beepSound) {
            this.beepSound.volume = this.volume;
        }
    }
};

// Create a simple beep using Web Audio API as fallback
Audio.createBeep = function() {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);

        oscillator.frequency.value = 800;
        oscillator.type = 'sine';

        gainNode.gain.setValueAtTime(this.volume * 0.3, audioCtx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.1);

        oscillator.start(audioCtx.currentTime);
        oscillator.stop(audioCtx.currentTime + 0.1);
    } catch (e) {
        // Web Audio not supported
    }
};
