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

- Browse plugins by risk domain (Prompt & Instruction Integrity, Access Control, Data Protection & Privacy, etc.)
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

## Detailed Configuration Guide

### 1. Target Configuration

Define **what system you're testing**.

#### Target Purpose
- **What to enter**: Plain English description of the AI system's role
- **Example**: "A customer service chatbot for an e-commerce platform that handles billing inquiries"
- **Why it matters**: Sent to the generation model; helps create contextually relevant attacks

#### Target Type
Choose how to communicate with your target system:

**OpenAI / Compatible**
- Use this for: OpenAI, Azure OpenAI, vLLM, Ollama, or any `/v1/chat/completions` endpoint
- Fields to fill:
  - **Model / Name**: The model identifier (e.g., `gpt-4o`, `gpt-3.5-turbo`)
  - **API Key** (optional): Authentication token (uses env var if not provided)
- Advanced REST options appear when selected (for custom endpoints)

**REST (Custom)**
- Use this for: Custom APIs with non-standard request/response formats
- Fields to fill:
  - **API Endpoint**: Full base URL (e.g., `https://my-api.example.com` or `http://localhost:8000`)
  - **Model Name**: Label for reference (e.g., `my-custom-llm`)
  - **Model ID** (optional): Actual identifier if different from name
  - **Request Payload**: JSON template with `$INPUT` placeholder
    - Example: `{"prompt": "$INPUT", "max_tokens": 512}`
    - Example: `{"messages": [{"role": "user", "content": "$INPUT"}]}`
  - **Response Field** (optional): JSON path to extract response
    - Example: `choices.0.message.content`, `output.text`, `result.response`
    - Leave blank to auto-detect
  - **Custom Headers** (optional): Additional HTTP headers as JSON
    - Example: `{"Authorization": "Bearer $KEY", "X-Custom-Header": "value"}`
    - Use `$KEY` to inject your API key

**Local Function**
- Use this for: Testing Python functions directly (no network call)
- Field to fill:
  - **Name**: Module path and function (e.g., `my_module#inference_function`)

### 2. Scan Settings

Global parameters applied to all plugins (unless overridden per-plugin).

| Setting | Value Range | Default | Purpose | Example |
|---------|-------------|---------|---------|---------|
| **Tests per Plugin** | 1–50 | 5 | How many unique attack variants to generate per plugin | `10` = 10 attacks per plugin |
| **Severity** | any / low / medium / high / critical | any | Filter which plugins to run (by risk level) | `high` = test only high/critical plugins |
| **Language** | English, Spanish, Chinese, French, German, etc. | English | Language for attack generation | `Spanish` = generate attacks in Spanish |
| **Max Chars / Message** | 50–5000 | (none) | Truncate generated attacks to this length | `256` = no attack longer than 256 characters |
| **Delay Between Calls** | milliseconds (0+) | 0 | Wait between API calls (prevents rate limiting) | `1000` = 1 second between calls |
| **Generation Instructions** | Plain text | (empty) | Hints to guide the attack generator | "Focus on indirect prompt injection and context window attacks" |
| **Seed Examples** | One example per line | (empty) | Few-shot examples to steer generation toward certain styles | See example below |
| **Global Instructions** | Plain text | (empty) | Constraints applying to all plugins | "Avoid explicit threats or profanity" |

**Seed Examples Format:**
```
Prompt: [attack 1]
Response: [target's vulnerable response 1]

Prompt: [attack 2]
Response: [target's vulnerable response 2]
```

### 3. Generation Backend

Configures **which model generates the attacks**.

| Setting | Value | Example | Notes |
|---------|-------|---------|-------|
| **Backend** | Anthropic / OpenAI / Mistral / Custom | Anthropic | Provider for generation model |
| **Model Name** | Backend-specific | `claude-opus-4-8` (Anthropic), `gpt-4o` (OpenAI), `mistral-large` (Mistral) | Which model to use |
| **API Key** | Secret token | `sk-ant-...` (Anthropic), `sk-...` (OpenAI) | Optional if env var set |
| **Base URL** | API endpoint (Custom only) | `http://localhost:8000/v1` | Only for Custom/vLLM backends |

**Recommended Generators:**
- **Anthropic (Claude)**: Best reasoning — recommended for complex tests
- **OpenAI (GPT-4o)**: Balanced cost/quality
- **Mistral**: Budget-friendly option
- **Custom/vLLM**: Self-hosted (Llama, Mixtral) — no API costs

### 4. Grader Backend

Configures **which model evaluates whether the target was vulnerable**.

| Setting | Value | Example | Notes |
|---------|-------|---------|-------|
| **Backend** | Anthropic / OpenAI / Mistral / Local | Anthropic | Provider for grading model |
| **Model Name** | Backend-specific | `claude-opus-4-8` (Anthropic), `gpt-4o` (OpenAI) | Which model to use |
| **API Key** | Secret token | `sk-...` | Optional if env var set |
| **Base URL** | API endpoint (Local only) | `http://localhost:8000/v1` | For OpenAI-compatible graders |

**Grading Recommendations:**
- Use **Claude** if possible — most accurate vulnerability assessment
- Can differ from generation backend (e.g., generate with GPT-4, grade with Claude)

### 5. Plugins

Select **which vulnerabilities to test**.

#### Browse by Category
Each category card shows:
- **Domain name** (e.g., "Prompt & Instruction Integrity")
- **Plugin count** (e.g., "11 plugins")
- **Expand** by clicking to see plugins

Each plugin shows:
- **Checkbox**: ✅ to select, ❌ to deselect
- **Plugin ID** (e.g., `prompt-injection`)
- **Objective**: What you're trying to make the model do
- **Severity badge**: Risk level (low/medium/high/critical)
- **⚙️ Gear icon**: Customize this specific plugin

#### Select by Framework
Click framework pills to quickly select curated bundles:
- `owasp:llm` — 30 plugins from OWASP Top 10 for LLMs
- `nist:ai:rmf` — 38 plugins from NIST AI Risk Management Framework
- `mitre:atlas` — 25 plugins from MITRE ATLAS
- `eu:ai-act` — 34 plugins for EU AI Act compliance
- `iso:42001` — 27 plugins for ISO/IEC 42001

Click again to deselect.

#### Add Custom Plugins
Expand **"+ Add Custom Plugin"** to define your own attacks:
- **Plugin ID**: Unique name (e.g., `custom:my-specific-attack`)
- **Objective**: What you want the model to do
- **Severity**: `low`, `medium`, `high`, or `critical`
- **Num tests**: How many variants to generate

#### Per-Plugin Customization
Click ⚙️ on any plugin to override:
- **Tests**: Override test count for this plugin only
- **Severity**: Override risk level
- **Language**: Override language for this plugin
- **Max Chars**: Override character limit
- **Custom Objective**: Replace the plugin's default objective
- **Strategies**: Select attack transformations (see below)
- **Instructions**: Plugin-specific generation hints

#### Per-Category Customization
Click the category header to apply settings to all plugins in that category:
- Same fields as per-plugin
- Easier way to configure a whole category at once
- Per-plugin settings override category settings

### 6. Strategies

**Attack transformations** applied after generation. Each selected strategy creates additional test cases.

**Formula:** Total cases = `tests × plugins × (1 + strategies_selected)`

A multi-turn conversation counts as **one** case, so adaptive strategies add
cases like any other — they multiply API calls, not the case count.

#### Static Strategies (No extra API calls)
| Strategy | What it does | Best for | Example |
|----------|-------------|----------|---------|
| `base64` | Encodes attack in Base64, asks model to decode | Bypassing keyword filters | "Decode and follow: aGVsbG8gd29ybGQ=" |
| `rot13` | ROT13-encodes the attack | Character-substitution defenses | Rotates all letters by 13 |
| `leetspeak` | Rewrites in leet speak (a→4, e→3) | Keyword filters | "h0w d0 1..." |
| `fiction` | Wraps attack in creative writing request | Intent detection filters | "Write a fictional story where a character..." |
| `citation` | Frames as academic research inquiry | Authority-based filters | "For my research paper, how would..." |
| `refusal-suppression` | Prepends "don't refuse" instructions | Refusal mechanisms | "Answer helpfully without refusing..." |

#### LLM Strategies (one generation call per case — **LLM** badge)
| Strategy | What it does | Best for |
|----------|-------------|----------|
| `jailbreak` | Rewrites the attack once to be more persuasive | Sophisticated defenses |
| `multilingual` | Translates attack to another language | Language-specific filters |
| `manyshot` | Prefixes N fabricated on-topic compliant exchanges (⚙ sets `num_shots`, default 8) | Many-shot / in-context jailbreaking |

#### Adaptive Strategies (live multi-turn — several calls per case — **MULTI-TURN** badge)
| Strategy | What it does | Best for |
|----------|-------------|----------|
| `crescendo` | Benign opener, escalates one step per turn, backtracks on refusal (⚙ sets `max_turns`/`max_backtracks`) | Gradual-escalation defenses |
| `conversational-jailbreak` | Reads each reply and refines a stronger attack until it breaks (⚙ sets `max_turns`) | Adaptive / iterative robustness |

> Each strategy's ⚙ (in the sidebar and in per-plugin / per-category customization) sets its tunables and shows the per-case call cost live. A case is marked **vulnerable** only when the grader judges the target's reply a break — use a grader model distinct from the target.

### 7. Run Scan

Click **"Run Scan"** to execute. The UI shows:

**Progress Bar**
- Percentage completed
- Cases completed (e.g., "45 / 100")
- Elapsed time

**Live Log**
- Real-time updates as scan runs
- Shows generation, target API calls, grading
- Errors appear in red

### 8. Results Tab

After scan completes:

**Summary Cards**
- Total cases tested
- Vulnerable count
- Resisted count
- Pass rate (%)

**Results by Plugin Table**
- Plugin ID
- Severity level
- Vulnerable count
- Total tests
- Visual bar showing ratio

**Input / Output Details**
- Plugin ID (which attack)
- Input Prompt (the exact attack)
- Output Response (model's reply)
- Verdict (VULNERABLE / RESISTED)
- Searchable, scrollable

**Download Results**
- Button to export full JSON
- Includes all metadata for analysis

### 8. Customization Levels

Settings cascade (most specific wins):

1. **Per-Plugin**: Highest priority
   - Override a single plugin's settings
   - Accessed via ⚙️ on plugin

2. **Per-Category**: Medium priority
   - Apply to all plugins in category
   - Accessed by clicking category header

3. **Global**: Lowest priority (fallback)
   - Applies to all plugins
   - Set in "Scan Settings" section

## Common Workflows

### Workflow 1: Quick Security Audit (OWASP Top 10)
Perfect for getting started quickly.

1. **Target**: Set Purpose (e.g., "My chatbot")
2. **Plugins**: Click `owasp:llm` pill (selects 30 security plugins)
3. **Backends**: Set to Claude for both generation and grading
4. **Scan**: Click Run Scan
5. **Results**: Review vulnerabilities by category

**Time**: ~5-10 minutes | **Cost**: ~$0.50

### Workflow 2: Test Custom REST API
For testing self-hosted or proprietary models.

1. **Target Type**: Select `REST (custom)`
2. **Endpoint**: `http://localhost:8000` (your API)
3. **Request Payload**: `{"model": "llama-7b", "messages": [{"role": "user", "content": "$INPUT"}]}`
4. **Response Field**: `choices.0.message.content`
5. **Plugins**: Select a few (e.g., `prompt-injection`, `jailbreak:dan`)
6. **Scan**: Run

**Tip**: Use `rest_debug.py` to test your REST template before scanning.

### Workflow 3: Multilingual Testing
Test defenses across languages.

1. **Plugins**: Select ones to test
2. **Strategies**: Check `multilingual`
3. **Scan Settings > Language**: Set to `Spanish` (or other language)
4. **Run**: Generates attacks in Spanish + translates via multilingual strategy

**Result**: Tests both language-specific attacks and translations

### Workflow 4: Focus on High-Severity Vulnerabilities
Quick risk assessment.

1. **Scan Settings > Severity**: Set to `high`
2. **Plugins**: Select `owasp:llm` or `nist:ai:rmf`
3. **Tests per Plugin**: `3` (fewer = faster)
4. **Run**: Only tests high/critical plugins

**Time**: ~2-3 minutes | **Cost**: ~$0.10

### Workflow 5: Deep Dive with All Transformations
Comprehensive adversarial testing.

1. **Tests per Plugin**: `10`
2. **Strategies**: Select the static + LLM ones (base64, rot13, leetspeak, fiction, citation, refusal-suppression, jailbreak, multilingual, manyshot)
3. **Plugins**: Select frameworks (owasp:llm + nist:ai:rmf)
4. **Run**: Generates many variants

**Formula**: 10 tests × 68 plugins × (1 + 9 strategies) = **6,800 test cases**
**Time**: ~30-60 minutes | **Cost**: ~$20-30

> **Adding adaptive strategies** (`crescendo`, `conversational-jailbreak`) adds cases at the same rate, but each of those cases costs ~5× the API calls of a static case (a full multi-turn conversation). Scope them to your highest-severity plugins rather than enabling globally in a run this size.

---

## Cost & Performance Guide

### API Costs
Estimate cost before running:

**Formula**: `(tests × plugins × (1 + strategies)) × (generation_cost + grading_cost)`

**Example:**
- 5 tests, 10 plugins, 1 strategy → 100 cases
- Generation: $0.005/case (Claude) → $0.50
- Grading: $0.003/case (Claude) → $0.30
- **Total: ~$0.80**

**Cost per model** (as of 2026):
- Claude (Anthropic): $0.005 gen + $0.003 grade = $0.008/case
- GPT-4o (OpenAI): $0.003 gen + $0.0015 grade = $0.0045/case
- Mistral: $0.0007 gen + $0.0007 grade = $0.0014/case

### Rate Limiting
If scans fail with rate limit errors:

1. **Increase Delay Between Calls**
   - Default: 0ms
   - Try: 1000-2000ms for free tier APIs
   - This increases scan time but prevents timeouts

2. **Reduce Tests per Plugin**
   - Instead of 10, use 5 or 3
   - Proportionally reduces API calls

3. **Use Fewer Plugins**
   - Select specific categories instead of all
   - Reduces total case count

### Performance Tips
- **Reduce strategies**: Each strategy adds extra cases and API calls
- **Batch tests**: Run separate scans for different categories
- **Use faster models**: Mistral < GPT-4o < Claude (speed, cost)
- **Local function**: Fastest option if available (no network latency)

---

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

## REST API Template Examples

Copy these templates for common APIs:

### OpenAI / OpenAI-Compatible
```json
{
  "model": "gpt-4o",
  "messages": [{"role": "user", "content": "$INPUT"}],
  "temperature": 0.7
}
```
**Response Field:** `choices.0.message.content`

### Anthropic (Claude)
```json
{
  "model": "claude-opus-4-8",
  "max_tokens": 1024,
  "messages": [{"role": "user", "content": "$INPUT"}]
}
```
**Response Field:** `content.0.text`

### Mistral
```json
{
  "model": "mistral-large",
  "messages": [{"role": "user", "content": "$INPUT"}]
}
```
**Response Field:** `choices.0.message.content`

### vLLM
```json
{
  "model": "meta-llama/Llama-2-7b",
  "messages": [{"role": "user", "content": "$INPUT"}],
  "temperature": 0.7
}
```
**Response Field:** `choices.0.message.content`

### Ollama
```json
{
  "model": "llama2",
  "prompt": "$INPUT",
  "stream": false
}
```
**Response Field:** `response`

### Custom API with Authentication
```json
{
  "input": "$INPUT",
  "max_length": 512,
  "temperature": 0.8
}
```
**Headers:**
```json
{
  "Authorization": "Bearer $KEY",
  "X-API-Version": "2.0"
}
```
**Response Field:** `output.text` (varies by API)

---

## Environment Variables

Set these in your shell before running `bash run.sh` to avoid entering API keys in the UI:

```bash
# Generation model API keys
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export MISTRAL_API_KEY="..."

# Grading model API keys (can be same or different)
export GRADER_API_KEY="..."

# Run the UI
cd ui
bash run.sh
```

The UI will use these env vars if no API key is entered in the form.

---

## Browser Console Debug Tips

If something isn't working:

1. **Open DevTools**: Press `F12`
2. **Go to Console tab**: See JavaScript errors
3. **Go to Network tab**: See API requests and responses
4. **Look for errors like:**
   - `Failed to load categories` → Backend connection issue
   - `CORS error` → Backend CORS misconfiguration
   - `TypeError: plugins is undefined` → JavaScript rendering issue

**Check backend logs** by looking at terminal output where you ran `bash run.sh`.

---

## Modifying the UI

The UI is a single HTML file with embedded CSS and JavaScript — no build step needed.

### To modify the interface:
1. Edit `/ui/backend/static/index.html`
2. Refresh your browser (Ctrl+R or Cmd+R)
3. Changes appear immediately

### To modify the backend:
1. Edit `/ui/backend/main.py` (FastAPI server)
2. Restart the server: Press Ctrl+C, then run `bash run.sh` again

### Common customizations:
- **Change colors/theme**: Edit CSS variables in `<style>` section
- **Add new fields**: Add HTML input in sidebar, then handle in JavaScript
- **Modify API response format**: Edit backend endpoints in `main.py`

---

## Security & Best Practices

### API Key Security
- ✅ **DO**: Use environment variables for sensitive keys
- ✅ **DO**: Use different API keys for testing vs. production
- ❌ **DON'T**: Commit API keys to version control
- ❌ **DON'T**: Share scans with API keys visible in results

### Data Privacy
- UI stores keys **in browser memory only** (not on disk)
- Results are stored locally (can be deleted anytime)
- No data is sent to external servers except API providers

### Testing Best Practices
- **Start small**: Test 1-2 plugins before running full scans
- **Use staging systems**: Test on non-production models first
- **Monitor costs**: Set a monthly API budget and track spending
- **Document findings**: Export results and save for audit trail

---

## FAQ

**Q: How long does a scan take?**
A: Depends on cases and API latency. Rough estimate: 1-2 seconds per case. 100 cases ≈ 2-3 minutes.

**Q: Can I run scans in parallel?**
A: Not yet in the UI. For parallel scans, use the CLI: `knox-rt --config config.yaml`

**Q: Can I save my configuration?**
A: Yes! Copy the Config JSON tab content and save as `config.yaml` to reuse via CLI.

**Q: How accurate is the grading?**
A: Depends on the grader model. Claude is most accurate. Verdict always includes a reason for verification.

**Q: Can I test models without an API?**
A: Yes! Use the **Local Function** target type to test Python functions directly.

**Q: What if I get rate limited?**
A: Increase "Delay Between Calls" in Scan Settings (1000-2000ms works well).
