# Knox-RT Web UI

A modern web interface for the Knox-RT LLM red teaming tool.

## Getting Started

### Clone the repository

```bash
git clone https://github.com/accuknox/redTeam.git
cd redTeam
```

### Quick Start

The easiest way to launch the UI is with the startup script:

```bash
cd ui
bash run.sh
```

This will:
1. Create a Python virtual environment (if needed)
2. Install all dependencies
3. Start the backend server on **http://localhost:8080**
4. Open the UI in your browser

## Features

✨ **Interactive Configuration**
- Visual target setup (OpenAI, REST, local function)
- Browse plugins organized by security categories
- Customize each plugin individually or by category
- Real-time scan progress tracking

🎯 **Flexible Attack Setup**
- Select plugins by category or individually
- Configure generation and grading backends (Anthropic, OpenAI, Mistral)
- Customize test counts, severity levels, language, and character limits
- Add custom plugins and attack strategies on the fly

📊 **Results Analysis**
- Real-time progress updates with elapsed time
- Detailed results table with attack prompts and model responses
- Summary statistics (total cases, vulnerable count, pass rate)
- Download results as JSON for further analysis

## How to Use

### 1. Configure Your Target

Set up what you want to test:
- **Purpose**: Describe the AI system (e.g., "A customer-support chatbot")
- **Type**: Choose OpenAI-compatible, REST API, or local Python function
- **Credentials**: Add API keys if required

### 2. Select Plugins & Attacks

- Browse plugins by security category (Access Control, Privacy, Code Execution, etc.)
- Select individual plugins or use framework presets (OWASP, NIST)
- Customize each plugin's test count, severity, or attack instructions
- Add custom plugins with your own objectives

### 3. Configure Backends

Set up the models that will generate and grade attacks:
- **Generator** (Attack Model): Creates adversarial prompts (Claude, GPT-4, etc.)
- **Grader** (Evaluation Model): Scores whether the target was vulnerable
- Both can use different backends and API keys

### 4. Run the Scan

Click **Run Scan** to start. Watch real-time progress as the tool:
1. Generates attack prompts
2. Sends them to your target
3. Grades the responses
4. Reports vulnerabilities

### 5. Analyze Results

- View summary statistics
- Browse detailed input/output pairs for each attack
- Export results as JSON

## Configuration Reference

### Target Types

| Type | Use Case | Example |
|------|----------|---------|
| **OpenAI / Compatible** | Any OpenAI-like API | gpt-4o, Claude via API, local vLLM |
| **REST (Custom)** | Your own HTTP endpoint | Custom LLM, proprietary API |
| **Local Function** | Python callable in same process | Direct model testing |

### Scan Settings

- **Tests per Plugin**: How many attack prompts to generate per plugin
- **Severity Filter**: Only test specific severity levels
- **Language**: Generate attacks in different languages
- **Max Characters**: Limit prompt length
- **Generation Instructions**: Global hints for the attack model
- **Seed Examples**: Provide example attacks for few-shot learning

### Customization Levels

Settings cascade from specific to general:
1. **Plugin-level**: Override for a single plugin
2. **Category-level**: Apply to all plugins in a category
3. **Global**: Fallback for all plugins and categories

## Troubleshooting

### Backend won't start

**Error: "Address already in use"**
```bash
# Free up port 8080
lsof -ti:8080 | xargs kill -9
bash run.sh
```

**Error: "No module named fastapi"**
```bash
# Reinstall dependencies
pip install -r ui/backend/requirements.txt
```

### UI doesn't load

- Open http://localhost:8080 in your browser
- Check browser console (F12) for errors
- Ensure backend is running (you should see logs in the terminal)

### Plugins not showing

- Verify the backend is running
- Check that the main redTeam package is installed
- Look for errors in the backend terminal

### Scans fail

- Verify your API keys are correct
- Ensure the target is reachable (especially for REST/custom URLs)
- Check backend logs for error messages

## Architecture

- **Frontend**: Single-page app (HTML/CSS/JavaScript) — no build step needed
- **Backend**: Python FastAPI server with plugin system
- **Real-time Updates**: Server-Sent Events (SSE) for live progress
- **API**: REST endpoints for configuration, scanning, and results

## Testing Your Setup

After starting the UI with `bash run.sh`, verify everything is working:

### Check the backend is running
```bash
curl http://localhost:8080/api/categories
```
You should see a JSON response with all available plugin categories.

### Open the UI
Navigate to **http://localhost:8080** in your browser. You should see:
- ✅ Knox-RT header with green "connected" status
- ✅ Sidebar with Target, Scan Settings, Generation, Grading sections
- ✅ Plugin categories loading in the Plugins section
- ✅ Strategy options in the Strategies section

### Try a simple scan
1. Keep defaults or customize as desired
2. Click **Run Scan** in the sidebar
3. Watch real-time progress in the Run tab
4. Review results in the Results tab

## Modifying the UI

1. Edit `ui/backend/static/index.html`
2. Refresh your browser (no restart needed)
3. For backend changes, restart the server: `bash run.sh`

## Next Steps

- See the main project README for CLI usage and advanced options
- Review available plugins: Check the `plugins/` directory in the project root
- Explore attack strategies: Look at `strategies/` for different attack methods
- Customize the UI: Modify `ui/backend/static/index.html` for your needs
