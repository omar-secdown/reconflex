#!/bin/bash

echo "=============================================="
echo "   Reconflex v4.1 - Setup Script"
echo "=============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================
# Parse arguments
# ============================================
UPDATE_MODE=false

if [[ "$1" == "--update" || "$1" == "-u" ]]; then
    UPDATE_MODE=true
    echo -e "${YELLOW}[*]${NC} Update mode: Reinstalling all tools to latest versions"
    echo ""
fi

# Check if Go is installed
echo "[*] Checking for Go installation..."
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}[✓]${NC} Go is installed: $GO_VERSION"
else
    echo -e "${RED}[✗]${NC} Go is not installed!"
    echo "[!] Please install Go from: https://go.dev/doc/install"
    exit 1
fi

# Check if Python3 is installed
echo "[*] Checking for Python3 installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}[✓]${NC} Python3 is installed: $PYTHON_VERSION"
else
    echo -e "${RED}[✗]${NC} Python3 is not installed!"
    echo "[!] Please install Python3"
    exit 1
fi

# Add Go bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo "[*] Adding Go bin to PATH..."
    export PATH=$PATH:$HOME/go/bin
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo -e "${GREEN}[✓]${NC} Go bin added to PATH"
fi

# ============================================
# Install Go tools
# ============================================
echo ""
echo "=============================================="
echo "   Installing Required Go Tools"
echo "=============================================="
echo ""

install_go_tool() {
    local name=$1
    local package=$2
    local step=$3
    local total=$4

    if [[ "$UPDATE_MODE" == true ]] || ! command -v "$name" &> /dev/null; then
        echo "[${step}/${total}] Installing ${name}..."
        go install -v "$package" 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${NC} ${name} installed successfully"
        else
            echo -e "${RED}[✗]${NC} ${name} installation failed"
        fi
    else
        echo -e "[${step}/${total}] ${GREEN}[✓]${NC} ${name} already installed (use --update to reinstall)"
    fi
    echo ""
}

install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest" 1 6
install_go_tool "alterx" "github.com/projectdiscovery/alterx/cmd/alterx@latest" 2 6
install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" 3 6
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" 4 6
install_go_tool "anew" "github.com/tomnomnom/anew@latest" 5 6
install_go_tool "massdns" "github.com/blechschmidt/massdns/cmd/massdns@latest" 6 6

# massdns might not be installable via go install - try system package manager
if ! command -v massdns &> /dev/null; then
    echo "[*] massdns not found via Go, trying system package manager..."

    if command -v apt-get &> /dev/null; then
        echo "[*] Trying apt-get..."
        apt-get update -qq && apt-get install -y -qq massdns 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${NC} massdns installed via apt-get"
        else
            echo "[*] apt-get failed, building from source..."
            # Build from source
            git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
            if [ -d /tmp/massdns ]; then
                cd /tmp/massdns && make 2>&1
                if [ -f /tmp/massdns/bin/massdns ]; then
                    cp /tmp/massdns/bin/massdns /usr/local/bin/massdns
                    chmod +x /usr/local/bin/massdns
                    echo -e "${GREEN}[✓]${NC} massdns built and installed from source"
                else
                    echo -e "${RED}[✗]${NC} massdns build failed"
                fi
                rm -rf /tmp/massdns
                cd - > /dev/null
            fi
        fi
    elif command -v brew &> /dev/null; then
        echo "[*] Trying Homebrew..."
        brew install massdns
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${NC} massdns installed via Homebrew"
        fi
    else
        echo -e "${YELLOW}[!]${NC} Could not install massdns automatically"
        echo "    Install manually: https://github.com/blechschmidt/massdns"
    fi
fi

# ============================================
# Install Shodan
# ============================================
echo ""
echo "=============================================="
echo "   Installing Shodan CLI"
echo "=============================================="
echo ""

echo "[*] Installing Shodan..."
pip install shodan --break-system-packages 2>/dev/null || pip install shodan

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Shodan installed successfully"
    echo -e "${YELLOW}[!]${NC} Don't forget to configure Shodan with: shodan init YOUR_API_KEY"
else
    echo -e "${RED}[✗]${NC} Shodan installation failed"
fi

# ============================================
# Install Python dependencies
# ============================================
echo ""
echo "=============================================="
echo "   Installing Python Dependencies"
echo "=============================================="
echo ""

if [ -f requirements.txt ]; then
    echo "[*] Installing from requirements.txt..."
    pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${NC} Python dependencies installed"
    else
        echo -e "${RED}[✗]${NC} Some Python dependencies failed to install"
    fi
else
    echo -e "${YELLOW}[!]${NC} requirements.txt not found, skipping"
fi

# ============================================
# Validate
# ============================================
echo ""
echo "=============================================="
echo "   Validating Configuration"
echo "=============================================="
echo ""

python3 config.py

# ============================================
# Tool verification
# ============================================
echo ""
echo "=============================================="
echo "   Tool Verification"
echo "=============================================="
echo ""

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $1"
    else
        echo -e "  ${RED}[✗]${NC} $1"
    fi
}

check_tool httpx
check_tool alterx
check_tool shuffledns
check_tool subfinder
check_tool anew
check_tool massdns
check_tool shodan

# Final message
echo ""
echo "=============================================="
echo "   Setup Complete!"
echo "=============================================="
echo ""
echo -e "${GREEN}[✓]${NC} All tools installed"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and configure your API keys"
echo "2. Initialize Shodan: shodan init YOUR_API_KEY"
echo "3. Run validation: python3 config.py"
echo "4. Start scanning: python3 reconflex.py -u example.com"
echo ""
echo "Update tools later with: ./setup.sh --update"
echo ""
