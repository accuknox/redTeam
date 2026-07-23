#!/bin/bash
# Knox-RT Web UI - Startup Script

SCRIPT_DIR="$(dirname "$0")"
BACKEND_DIR="$SCRIPT_DIR/backend"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$BACKEND_DIR"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install core redTeam dependencies
echo "Installing core dependencies..."
pip install -r "$ROOT_DIR/requirements.txt" -q

# Install UI-specific dependencies
echo "Installing UI dependencies..."
pip install -r requirements.txt -q

# Start the backend
echo ""
echo "✅ Knox-RT UI Backend starting on http://localhost:8080"
echo ""
python main.py
