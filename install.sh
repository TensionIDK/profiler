#!/bin/sh
# PROFILER v2.0 - Portable Installer
# Usage: sh install.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$SCRIPT_DIR/profiler.py"

if [ ! -f "$TARGET" ]; then
    echo "ERROR: profiler.py not found in $SCRIPT_DIR"
    exit 1
fi

# Install to /usr/bin (requires write access / sudo)
if [ -w /usr/bin ]; then
    cp "$TARGET" /usr/bin/profiler
    chmod +x /usr/bin/profiler
    echo "Installed to /usr/bin/profiler"
elif command -v sudo >/dev/null 2>&1; then
    sudo cp "$TARGET" /usr/bin/profiler
    sudo chmod +x /usr/bin/profiler
    echo "Installed to /usr/bin/profiler (via sudo)"
else
    mkdir -p "$HOME/.local/bin"
    cp "$TARGET" "$HOME/.local/bin/profiler"
    chmod +x "$HOME/.local/bin/profiler"
    echo "Installed to $HOME/.local/bin/profiler"
    echo "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "PROFILER v2.0 installed. Run 'profiler' to start."
echo "To configure an AI provider: profiler ai config"
