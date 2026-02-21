#!/bin/bash

# profile-bee installer script
# Downloads and installs the latest release of profile-bee from GitHub

set -e

# Configuration
REPO="zz85/profile-bee"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="probee"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS and architecture
detect_platform() {
    local os
    local arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux*)
            OS="linux"
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $os${NC}"
            echo "profile-bee currently only supports Linux"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $arch${NC}"
            echo "profile-bee currently supports x86_64 and aarch64 architectures"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    echo -e "${GREEN}Detected platform: ${PLATFORM}${NC}"
}

# Get the latest release version
get_latest_version() {
    echo "Fetching latest release version..."

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        echo -e "${RED}Error: Neither curl nor wget found. Please install one of them.${NC}"
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        echo -e "${RED}Error: Could not fetch latest version${NC}"
        exit 1
    fi

    echo -e "${GREEN}Latest version: ${VERSION}${NC}"
}

# Download and extract the release
download_and_install() {
    local tarball="profile-bee-${PLATFORM}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${tarball}"
    local temp_dir
    temp_dir=$(mktemp -d)

    echo "Downloading profile-bee ${VERSION} for ${PLATFORM}..."

    if command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "${temp_dir}/${tarball}"
    else
        wget -q "$url" -O "${temp_dir}/${tarball}"
    fi

    if [ ! -f "${temp_dir}/${tarball}" ]; then
        echo -e "${RED}Error: Download failed${NC}"
        rm -rf "$temp_dir"
        exit 1
    fi

    echo "Extracting binaries..."
    tar -xzf "${temp_dir}/${tarball}" -C "$temp_dir"

    # Create install directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"

    # Install binaries
    echo "Installing to ${INSTALL_DIR}..."
    mv "${temp_dir}/probee" "$INSTALL_DIR/"
    mv "${temp_dir}/pbee" "$INSTALL_DIR/"

    # Make binaries executable
    chmod +x "${INSTALL_DIR}/probee"
    chmod +x "${INSTALL_DIR}/pbee"

    # Create profibee symlink
    ln -sf "${INSTALL_DIR}/probee" "${INSTALL_DIR}/profibee"

    # Cleanup
    rm -rf "$temp_dir"

    echo -e "${GREEN}✓ Successfully installed profile-bee ${VERSION}${NC}"
}

# Check if install directory is in PATH
check_path() {
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        echo -e "${YELLOW}Warning: ${INSTALL_DIR} is not in your PATH${NC}"
        echo "Add the following line to your ~/.bashrc or ~/.zshrc:"
        echo ""
        echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
    fi
}

# Verify installation
verify_installation() {
    if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        echo ""
        echo -e "${GREEN}Installation verified!${NC}"
        echo ""
        echo "Run 'probee --help' to get started"
        echo "Note: profile-bee requires root privileges to run (uses eBPF)"
        echo ""
        echo "Quick start:"
        echo "  sudo probee --tui              # Interactive TUI flamegraph"
        echo "  sudo probee --svg out.svg      # Generate SVG flamegraph"
        echo ""
        return 0
    else
        echo -e "${RED}Error: Installation verification failed${NC}"
        return 1
    fi
}

# Main installation flow
main() {
    echo "profile-bee installer"
    echo "===================="
    echo ""

    detect_platform
    get_latest_version
    download_and_install
    verify_installation
    check_path
}

# Run main function
main
