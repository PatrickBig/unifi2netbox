#!/bin/sh

# Check if config.yaml exists
if [ ! -f /app/config/config.yaml ]; then
  echo "Error: /app/config/config.yaml not found."
  exit 1
fi


python main.py "$@"
