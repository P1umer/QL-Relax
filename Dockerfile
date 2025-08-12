FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && \
    apt-get -y install git build-essential cmake wget curl netcat socat net-tools \
    python3 python3-pip sudo xz-utils

# Create non-root user 'user'
RUN useradd -ms /bin/bash user && \
    usermod -aG sudo user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Install CodeQL
RUN wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.1/codeql-bundle-linux64.tar.gz && \
    tar -xzf codeql-bundle-linux64.tar.gz && \
    mv codeql /opt/codeql && \
    rm codeql-bundle-linux64.tar.gz

# Download and install Node.js 18 manually
RUN curl -fsSL https://nodejs.org/dist/v18.20.8/node-v18.20.8-linux-x64.tar.xz -o node.tar.xz && \
    mkdir -p /opt/node && \
    tar -xf node.tar.xz -C /opt/node --strip-components=1 && \
    rm node.tar.xz && \
    ln -s /opt/node/bin/node /usr/local/bin/node && \
    ln -s /opt/node/bin/npm /usr/local/bin/npm

# Switch to non-root user
USER user
WORKDIR /home/user

# Install Claude Code and SDK
RUN npm install --prefix ~/.local @anthropic-ai/claude-code && \
    python3 -m pip install --user claude-code-sdk

# Set PATH for pip and npm user-level installs
ENV PATH="/home/user/.local/bin:/home/user/.local/node_modules/.bin:$PATH"

# Set working directory
WORKDIR /workspace

# Default command
CMD ["bash"]