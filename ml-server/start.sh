#!/bin/bash

echo "=== Starting GoUpload ML Server ==="

# Check if Python virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create models directory
mkdir -p models

# Start server
echo "Starting ML server on port 5000..."
uvicorn model_server:app --host 0.0.0.0 --port 5000 --reload
