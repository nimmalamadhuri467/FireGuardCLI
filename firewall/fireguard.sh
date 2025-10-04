#!/bin/bash
# FireGuardCLI Launch Script

# Change to script directory
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run FireGuardCLI with arguments
python main.py "$@"
