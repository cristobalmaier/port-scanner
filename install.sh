#!/bin/sh
# Instala netscope en tu PATH para poder ejecutarlo como `netscope <ip>`
# desde cualquier carpeta. No copia nada: crea un enlace al script del repo.
set -e

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN="${NETSCOPE_BIN:-$HOME/.local/bin}"

mkdir -p "$BIN"
ln -sf "$DIR/netscope" "$BIN/netscope"
chmod +x "$DIR/netscope"

echo "OK: netscope instalado en $BIN/netscope"
case ":$PATH:" in
    *":$BIN:"*) echo "Ya podés ejecutar:  netscope <ip>" ;;
    *) echo "AVISO: $BIN no está en tu PATH."
       echo "Agregalo (por ejemplo en ~/.profile o ~/.config/fish/config.fish) y abrí una terminal nueva." ;;
esac
