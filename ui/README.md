# Knox-RT Web UI

A modern web interface for Knox-RT LLM red teaming tool.

## Features

✨ **Interactive Configuration**
- Visual target setup (OpenAI, REST, local function)
- Category-based plugin browser
- Per-plugin and category-level customization
- Real-time scan progress tracking

🎯 **Flexible Attack Setup**
- Select plugins by category or individually
- Configure generation and grading backends
- Customize tests, severity, language, and max characters per plugin
- Add custom plugins and strategies

📊 **Results Analysis**
- Real-time progress updates
- Detailed results table with input/output pairs
- JSON export for further analysis
- Scan statistics and pass rates

## Quick Start

### Option 1: Using the startup script (Recommended)
```bash
cd /home/eshrath/redTeam/ui
bash run.sh
```

### Option 2: Manual setup
```bash
cd /home/eshrath/redTeam/ui/backend

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python main.py
```

The UI will be available at **http://localhost:8080**

## Configuration

### Target Setup
- **OpenAI / Compatible**: Configure any OpenAI-compatible API
- **REST (custom)**: Set up custom REST APIs with template support
- **Local function**: Test Python callables locally

### Scan Settings
- Tests per plugin (default: 5)
- Global severity level
- Language selection
- Generation and seed examples
- Global instructions for all plugins

### Plugins & Categories
Browse plugins by category:
- 🔒 Security & Access Control
- 🔐 Privacy & Data Protection
- 💻 Code Execution
- And more...

Each plugin can be customized individually with:
- Custom test count
- Severity override
- Language override
- Custom objective
- Plugin-specific instructions
- Attack strategies (base64, rot13, jailbreak, etc.)

## Backend Requirements

The UI requires the Knox-RT backend (`/home/eshrath/redTeam/`) to be properly set up with:
- Plugin modules
- Strategy implementations
- Grading/detection system

See the main `README.md` in the redTeam directory for backend setup instructions.

## Architecture

- **Frontend**: HTML/CSS/JavaScript with no external dependencies (self-contained)
- **Backend**: FastAPI + Server-Sent Events (SSE) for real-time updates
- **Communication**: REST API with WebSocket-style streaming

## Troubleshooting

**"Address already in use" error**
```bash
# Kill the process on port 8080
lsof -ti:8080 | xargs kill -9
```

**Missing dependencies**
```bash
pip install -r requirements.txt
```

**Cannot connect to API**
- Ensure backend is running on http://localhost:8080
- Check firewall settings
- Verify browser console for CORS errors

## Development

To modify the UI:
1. Edit files in `backend/static/index.html`
2. Refresh the browser (no build step needed)
3. Backend changes require server restart
