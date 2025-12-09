#!/bin/bash
# Entrypoint script to ensure liboqs is found at runtime

# Update library cache
ldconfig

# Verify liboqs is accessible
if [ ! -f /usr/local/lib/liboqs.so ]; then
    echo "ERROR: liboqs.so not found at /usr/local/lib/liboqs.so"
    ls -la /usr/local/lib/liboqs* || echo "No liboqs files found"
    exit 1
fi

# Verify library can be loaded
python -c "import ctypes; ctypes.CDLL('/usr/local/lib/liboqs.so'); print('OK liboqs library verified')" || {
    echo "ERROR: Cannot load liboqs.so"
    exit 1
}

# Run the command (if any provided)
# If no command provided, start an interactive shell
if [ $# -eq 0 ]; then
    # No command provided, start bash shell
    exec /bin/bash
else
    # Command provided, run it
    exec "$@"
fi

