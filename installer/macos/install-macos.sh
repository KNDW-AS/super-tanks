#!/bin/bash
# Super Tanks macOS Installer
# Creates an app bundle that runs the Linux install.sh logic
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$HOME/Applications/Super Tanks.app"
INSTALL_DIR="$HOME/super-tanks"

echo "Super Tanks — macOS Installer"
echo ""

# Check for Docker Desktop
if ! command -v docker &>/dev/null; then
    echo "Docker Desktop is required."
    echo ""
    echo "Opening download page..."
    open "https://www.docker.com/products/docker-desktop/"
    echo ""
    echo "After installing Docker Desktop, run this script again."
    exit 1
fi

# Run the shared installer
cd "$SCRIPT_DIR/../.."
bash install.sh

echo ""
echo "To create a desktop shortcut, drag Super Tanks from"
echo "Applications to your Dock."
