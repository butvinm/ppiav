#!/usr/bin/env bash
# Provisioning script for ppiav FHE benchmark VPS.
# Run as ubuntu user on a fresh Ubuntu 22.04 VPS from immers.cloud (cpu.16.128.240 for logn16).
set -euxo pipefail

# Wait for cloud-init to finish before touching apt
sudo cloud-init status --wait || true

# Build deps
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    software-properties-common ca-certificates curl gnupg
# Ubuntu 22.04 ships python3.10; we need 3.12 — pull from deadsnakes PPA
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential libgmp-dev libssl-dev pkg-config \
    python3.12 python3.12-venv python3.12-dev \
    git curl jq

# Go 1.24+ from upstream (Ubuntu 22.04 has 1.18 by default)
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q 'go1.24\|go1.25\|go1.26'; then
    curl -sSLo /tmp/go.tar.gz https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh > /dev/null
export PATH=$PATH:/usr/local/go/bin

# uv
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc

# Clone repo (unauthenticated - branch pushed to GitHub)
if [ ! -d ~/ppiav ]; then
    git clone https://github.com/butvinm/ppiav.git ~/ppiav
fi
cd ~/ppiav
git fetch origin phase-3-http-services-and-browser-spas
git checkout phase-3-http-services-and-browser-spas

# Install Python dependencies via uv
cd ~/ppiav/models
uv sync

# UTKFace dataset via kagglehub
# Requires ~/.kaggle/kaggle.json or KAGGLE_USERNAME/KAGGLE_KEY env vars
if [ ! -f ~/.kaggle/kaggle.json ] && [ -z "${KAGGLE_USERNAME:-}" ]; then
    echo "ERROR: Kaggle credential not found"
    echo "Required: ~/.kaggle/kaggle.json or KAGGLE_USERNAME/KAGGLE_KEY env vars"
    exit 1
fi
uv run python -m models.utkface --target ./data/UTKFace

# Verify dataset
ls -la data/UTKFace/ 2>&1 | head -2

echo 'PROVISIONING DONE'
