#!/usr/bin/env bash
# Build PalisadeT4T.cap — two applets (FIDO2 + T4T) in one package.
# Requires: JDK 11, JavaCard 3.0.5 SDK
set -euo pipefail

export JAVA_HOME="${JAVA_HOME:-$(brew --prefix openjdk@11)/libexec/openjdk.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
export JC_HOME="${JC_HOME:-/Users/danderson/Documents/Claude Code/Palisade/Java_Card_Classic_API-3.0.5/Java_Card_Classic_API-3.0.5}"

echo "JAVA_HOME=$JAVA_HOME"
echo "JC_HOME=$JC_HOME"
echo ""

cd "$(dirname "$0")"
mkdir -p build
ant -f build.xml build

echo ""
echo "CAP: $(pwd)/build/PalisadeT4T.cap"
echo ""
echo "Install commands (GlobalPlatformPro):"
echo "  # Install both applets from one CAP"
echo "  gp --install build/PalisadeT4T.cap \\"
echo "     --module A0000006472F0001 --create A0000006472F0001 \\"
echo "     --params <FIDO2_INSTALL_DATA>"
echo ""
echo "  gp --install build/PalisadeT4T.cap \\"
echo "     --module A0000006470101 --create D2760000850101 \\"
echo "     --params <T4T_INSTALL_DATA>"
echo ""
echo "  T4T install data: uid(7) | picc_enc_key(16) | mac_key(16) | url_len(1) | url(N)"
