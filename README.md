# TRACE Frontend

Terminal-style interface for the TRACE OSINT tool.

## Quick Start

1. Start the backend first (see backend README)

2. Serve the frontend:
   ```bash
   cd frontend
   # Using Python
   python -m http.server 5500
   # Or using Node
   npx serve -p 5500
   ```

3. Open http://localhost:5500

## Pages

- `/` - Landing page with email input
- `/verify` - Verification code entry + depth selection
- `/scan` - Scan progress (placeholder)
- `/results` - Results receipt (placeholder)

## Configuration

Edit `js/api.js` to change the backend URL:
```javascript
API.setBaseUrl('http://localhost:8000/api');
```

## Structure

```
frontend/
├── index.html          # Single HTML file
├── css/
│   ├── main.css        # Base styles
│   ├── terminal.css    # Terminal components
│   └── components.css  # UI components
├── js/
│   ├── app.js          # Main application
│   ├── router.js       # Client-side routing
│   ├── api.js          # Backend communication
│   ├── terminal.js     # Typing effects
│   └── audio.js        # Sound effects
└── audio/
    └── beep.mp3        # Beep sound
```

## Next Steps

- Frontend Prompt 2: D3.js graph visualization
- Frontend Prompt 3: Receipt page + PDF generation
