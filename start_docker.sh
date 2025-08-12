#!/bin/bash
# Start script for QL-Relax Docker environment

set -e

echo "Setting up QL-Relax Docker environment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Build the image
echo "Building QL-Relax image..."
docker build -t ql-relax:latest .

# Check if container already exists
if docker ps -a --format '{{.Names}}' | grep -q '^ql-relax-container$'; then
    echo "Container 'ql-relax-container' already exists"
    # Start it if it's stopped
    docker start ql-relax-container
else
    # Create and run new container
    echo "Creating new container 'ql-relax-container'..."
    docker run -d \
        --name ql-relax-container \
        -v "$(pwd)":/workspace \
        -v "$(pwd)/juliet-test-suite-c":/workspace/juliet-test-suite-c \
        ql-relax:latest \
        tail -f /dev/null
fi

echo ""
echo "QL-Relax Docker environment is ready!"
echo "Container name: ql-relax-container"
echo ""
echo "You can now run QL-Relax commands:"
echo "  python3 run_juliet.py --cwe 190"
echo ""
echo "Or enter the container:"
echo "  docker exec -it ql-relax-container bash"