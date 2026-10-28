#!/bin/sh
# Recreate the synthetic docker.sock placeholder (git cannot store sockets).
SOCK="$(dirname "$0")/fixtures/sample-container/var/run/docker.sock"
[ -S "$SOCK" ] && exit 0
python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.bind('$SOCK'); s.close()"
