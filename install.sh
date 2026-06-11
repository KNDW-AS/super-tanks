#!/bin/bash
# Super Tanks Installer — Linux / macOS / Raspberry Pi
# Usage: curl -sSL https://aeris.no/install.sh | bash
set -e

REPO="https://github.com/kndw-as/super-tanks.git"
INSTALL_DIR="$HOME/super-tanks"
PORT=8765

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Super Tanks Installer           ║${NC}"
echo -e "${BLUE}║   Your AI home. Works offline.        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Check OS ──
OS="$(uname -s)"
ARCH="$(uname -m)"
echo -e "${GREEN}[1/7]${NC} Detected: $OS $ARCH"

if [[ "$OS" != "Linux" && "$OS" != "Darwin" ]]; then
    echo -e "${RED}Unsupported OS: $OS. Use install.exe for Windows.${NC}"
    exit 1
fi

# ── Step 2: Check/Install Docker ──
echo -e "${GREEN}[2/7]${NC} Checking Docker..."
if command -v docker &>/dev/null; then
    echo "  Docker found: $(docker --version | head -1)"
else
    echo "  Installing Docker..."
    if [[ "$OS" == "Linux" ]]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        echo -e "${YELLOW}  NOTE: You may need to log out and back in for Docker permissions.${NC}"
    elif [[ "$OS" == "Darwin" ]]; then
        echo -e "${YELLOW}  Please install Docker Desktop from https://docker.com/products/docker-desktop${NC}"
        echo "  Then run this script again."
        exit 1
    fi
fi

# ── Step 3: Check/Install Docker Compose ──
echo -e "${GREEN}[3/7]${NC} Checking Docker Compose..."
if docker compose version &>/dev/null; then
    echo "  Docker Compose found"
else
    echo -e "${RED}  Docker Compose not found. Please update Docker.${NC}"
    exit 1
fi

# ── Step 4: Download Super Tanks ──
echo -e "${GREEN}[4/7]${NC} Downloading Super Tanks..."
if [[ -d "$INSTALL_DIR" ]]; then
    echo "  Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --quiet 2>/dev/null || true
else
    if command -v git &>/dev/null; then
        git clone --quiet "$REPO" "$INSTALL_DIR"
    else
        echo "  Installing git..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y -qq git
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y -q git
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm git
        elif command -v brew &>/dev/null; then
            brew install git
        fi
        git clone --quiet "$REPO" "$INSTALL_DIR"
    fi
fi
cd "$INSTALL_DIR"

# ── Step 5: Create config if missing ──
echo -e "${GREEN}[5/7]${NC} Setting up configuration..."
if [[ ! -f .env ]]; then
    cat > .env << 'ENVEOF'
# Super Tanks Configuration
# Fill in your API keys (optional — system works offline with Ollama only)

# AI Providers (at least one required)
# GEMINI_API_KEY=
# MOONSHOT_API_KEY=
# OPENAI_API_KEY=

# Telegram (optional — for notifications)
# AERIS_TELEGRAM_TOKEN=
# ZEPH_TELEGRAM_TOKEN=
# AERIS_GOGATE_TELEGRAM_TOKEN=
# ADMIN_USER_ID=

# Home Assistant (optional — for smart home)
# HOMEASSISTANT_URL=http://homeassistant.local:8123
# HOMEASSISTANT_TOKEN=
ENVEOF
    echo "  Created .env template — edit later to add API keys"
else
    echo "  .env already exists"
fi

# ── Step 6: Start containers ──
echo -e "${GREEN}[6/7]${NC} Starting Super Tanks..."
echo "  This may take a few minutes on first run (downloading AI models)..."
docker compose up -d --build 2>&1 | while IFS= read -r line; do
    # Show simplified progress
    if echo "$line" | grep -q "Pull"; then
        echo "  Downloading components..."
    elif echo "$line" | grep -q "Started\|Running"; then
        echo "  Starting services..."
    fi
done

# Wait for health check
echo "  Waiting for system to be ready..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:$PORT/api/health" &>/dev/null; then
        break
    fi
    sleep 2
done

# ── Step 7: Open browser ──
echo -e "${GREEN}[7/7]${NC} Opening setup wizard..."
echo ""

SETUP_URL="http://localhost:$PORT/setup"

if command -v xdg-open &>/dev/null; then
    xdg-open "$SETUP_URL" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "$SETUP_URL" &
fi

echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Super Tanks is ready!             ║${NC}"
echo -e "${GREEN}║                                       ║${NC}"
echo -e "${GREEN}║  Setup:    ${NC}http://localhost:$PORT/setup${GREEN}  ║${NC}"
echo -e "${GREEN}║  Cockpit:  ${NC}http://localhost:$PORT${GREEN}       ║${NC}"
echo -e "${GREEN}║                                       ║${NC}"
echo -e "${GREEN}║  Stop:     docker compose down         ║${NC}"
echo -e "${GREEN}║  Start:    docker compose up -d         ║${NC}"
echo -e "${GREEN}║  Logs:     docker compose logs -f       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "Your AI home is ready. ${BLUE}Aeris is waiting.${NC}"
echo ""
