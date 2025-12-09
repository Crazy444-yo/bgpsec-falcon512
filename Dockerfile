FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (liboqs needs build tools and git)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    git \
    cmake \
    ninja-build \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs from source first (ensures it's available for liboqs-python)
# This prevents liboqs-python from trying to auto-install at runtime
RUN git clone --depth=1 --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    # Verify liboqs was installed correctly
    ls -la /usr/local/lib/liboqs* && \
    rm -rf /tmp/liboqs

# Set library path (must be set before installing liboqs-python AND at runtime)
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV OQS_SKIP_AUTO_INSTALL=1

# Copy requirements first (for better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
# Verify liboqs is accessible before installing liboqs-python
RUN ldconfig && \
    ls -la /usr/local/lib/liboqs* && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Verify liboqs-python can find the library
    python -c "import ctypes; lib = ctypes.CDLL('/usr/local/lib/liboqs.so'); print('✓ liboqs shared library accessible')" && \
    python -c "from oqs import Signature; s = Signature('Falcon-512'); print('✓ liboqs-python verified during build')" && \
    echo "liboqs installation verified successfully"

# Copy application code
COPY *.py .
COPY modules/ ./modules/

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create examples directory
RUN mkdir -p examples

# Set Python to unbuffered mode (for better logging)
ENV PYTHONUNBUFFERED=1

# Ensure LD_LIBRARY_PATH is set at runtime (redundant but ensures it's available)
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Entrypoint verifies liboqs is available before running commands
# If you want auto-start, uncomment the CMD below
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command (commented out - no auto-start)
# Uncomment the line below if you want docker-compose up to automatically run the test
#CMD ["python", "test_15hop.py"]


