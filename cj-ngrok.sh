#!/usr/bin/env bash
# Helpers y configuracion compartida (inlined).

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
    C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_CYA=$'\033[36m'
    C_MAG=$'\033[35m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYA=""
    C_MAG=""; C_BOLD=""
fi

log()  { echo "${C_BLU}[+]${C_RESET} $*"; }
ok()   { echo "${C_GRN}[✓]${C_RESET} $*"; }
warn() { echo "${C_YEL}[!]${C_RESET} $*" >&2; }
err()  { echo "${C_RED}[-]${C_RESET} $*" >&2; }
info() { echo "${C_CYA}[i]${C_RESET} $*"; }

html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

url_encode() {
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

port_free() {
    python3 -c "import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',int(sys.argv[1]))); s.close()" "$1" 2>/dev/null
}

find_free_port() {
    local start="${1:-8000}" p
    for p in $(seq "$start" $((start + 30))); do
        if port_free "$p"; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

clipboard_copy() {
    local text="$1"
    if command -v wl-copy >/dev/null 2>&1; then
        printf '%s' "$text" | wl-copy && return 0
    elif command -v xclip >/dev/null 2>&1; then
        printf '%s' "$text" | xclip -selection clipboard && return 0
    elif command -v xsel >/dev/null 2>&1; then
        printf '%s' "$text" | xsel -b && return 0
    fi
    return 1
}

show_qr() {
    local url="$1"
    if command -v qrencode >/dev/null 2>&1; then
        echo
        qrencode -t ANSIUTF8 "$url"
    fi
}

PIDS=()
TMPDIRS=()
register_pid()   { PIDS+=("$1"); }
register_tmpdir(){ TMPDIRS+=("$1"); }

cleanup_all() {
    local p d
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    for d in "${TMPDIRS[@]:-}"; do
        [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d"
    done
}

# ----------------------------------------------------------------------
# Banner / logo
# ----------------------------------------------------------------------
show_banner() {
    echo "${C_CYA}${C_BOLD}"
    cat <<'EOF'
      _ _      _     _            _    _                       _    
  ___| (_) ___| | __(_) __ _  ___| | _(_)_ __   __ _ _ __ ___ | | __
 / __| | |/ __| |/ /| |/ _` |/ __| |/ / | '_ \ / _` | '__/ _ \| |/ /
| (__| | | (__|   < | | (_| | (__|   <| | | | | (_| | | | (_) |   < 
 \___|_|_|\___|_|\_\/ |\__,_|\___|_|\_\_|_| |_|\__, |_|  \___/|_|\_\
                  |__/                         |___/                
EOF
    echo "${C_RESET}"
}

set -uo pipefail

# ----------------------------------------------------------------------
# cj-ngrok.sh - Clickjacking analysis + PoC sharing (local/ngrok)
#
# Uso:
#   ./cj-ngrok.sh <url> [opciones]
#   ./cj-ngrok.sh -l targets.txt [opciones]
#   ./cj-ngrok.sh serve <puerto> <archivo|directorio> [opciones]
#
# Opciones (analisis):
#   --fake-click     Inyecta overlay falso en el PoC HTML
#   --screenshot     Captura PNG del PoC con chromium headless
#   --verify         Verificacion dinamica de framing con chromium headless
#   --serve          Sirve el PoC por HTTP local (sin ngrok)
#   --share          Sirve el PoC y lo expone con ngrok (URL publica)
#   --local-only     Con --share, omite ngrok (solo local)
#   --port <n>       Puerto para servir/compartir (default: auto)
#   --open           Abre la URL servida/compartida en el navegador
#   --insecure       Desactiva verificacion TLS en curl (labs/CTF)
#   --no-browser     No abre firefox al terminar (CI / headless)
#   -l <file>        Archivo con una URL por linea
#   -o <dir>         Directorio de salida (default: ./cj_out)
#   --version        Version
#   -h, --help       Ayuda
#
# Exit code (modo single URL):
#   0 = PROTEGIDO   1 = VULNERABLE   2 = REVISAR MANUAL
#


VERSION="1.0.0"

UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

FAKE="false"
SCREENSHOT="false"
VERIFY="false"
NO_BROWSER="false"
OUTDIR="$PWD/cj_out"
LIST_FILE=""
TARGETS=()
SHARE="false"
SERVE="false"
LOCAL_ONLY="false"
OPEN_URL="false"
QR="false"
PORT=""
INSECURE="false"
MODE="analysis"
SHARE_PORT=""
SHARE_TARGET=""

usage() {
    show_banner
    cat <<'USAGE_EOF'
cj-ngrok.sh - Clickjacking analysis + PoC sharing (local/ngrok)

Uso:
  ./cj-ngrok.sh <url> [opciones]
  ./cj-ngrok.sh -l targets.txt [opciones]
  ./cj-ngrok.sh serve <puerto> <archivo|directorio> [opciones]

Opciones (analisis):
  --fake-click     Inyecta overlay falso en el PoC HTML
  --screenshot     Captura PNG del PoC con chromium headless
  --verify         Verificacion dinamica de framing con chromium headless
  --serve          Sirve el PoC por HTTP local (sin ngrok)
  --share          Sirve el PoC y lo expone con ngrok (URL publica)
  --local-only     Con --share, omite ngrok (solo local)
  --port <n>       Puerto para servir/compartir (default: auto)
  --open           Abre la URL servida/compartida en el navegador
  --qr             Muestra un codigo QR de la URL (requiere qrencode)
  --insecure       Desactiva verificacion TLS en curl (labs/CTF)
  --no-browser     No abre firefox al terminar (CI / headless)
  -l <file>        Archivo con una URL por linea
  -o <dir>         Directorio de salida (default: ./cj_out)
  --version        Version
  -h, --help       Ayuda

Exit code (modo single URL):
  0 = PROTEGIDO   1 = VULNERABLE   2 = REVISAR MANUAL

Requisitos: curl, python3. Opcionales: chromium, ngrok, firefox/xdg-open,
            qrencode, xclip/xsel/wl-copy.
USAGE_EOF
    exit "${1:-0}"
}

extract_last_header_block() {
    local file="$1"
    awk '
        BEGIN { block="" }
        { gsub(/\r/, "") }
        /^HTTP\// { block=$0 "\n"; next }
        /^[[:space:]]*$/ { next }
        { block = block $0 "\n" }
        END { printf "%s", block }
    ' "$file"
}

verify_framing() {
    local url="$1" html="$2"
    if ! command -v chromium >/dev/null 2>&1; then
        warn "--verify requiere chromium. Omitiendo."
        echo "ERROR"
        return
    fi
    local logf html_abs
    html_abs="$(realpath "$html" 2>/dev/null || echo "$html")"
    logf="$(mktemp)"
    timeout 90 chromium --headless=new --disable-gpu --no-sandbox \
        --virtual-time-budget=8000 --hide-scrollbars \
        --enable-logging --log-file="$logf" \
        "file://$html_abs" >/dev/null 2>&1 || true
    if grep -qiE "Refused to display|X-Frame-Options|frame-ancestors|Content Security Policy|violates the following|has been blocked|blocked" "$logf"; then
        echo "BLOCKED"
    elif [ -s "$logf" ]; then
        echo "FRAMED"
    else
        echo "ERROR"
    fi
    rm -f "$logf"
}

analyze_target() {
    local URL="$1"
    VERDICT_CODE=2
    VERDICT_TXT="REVISAR MANUAL"

    local TMPDIR HEADERS_RAW HEADERS
    TMPDIR="$(mktemp -d)"
    register_tmpdir "$TMPDIR"
    HEADERS_RAW="$TMPDIR/headers_raw.txt"
    HEADERS="$TMPDIR/headers.txt"

    echo
    echo "${C_BOLD}${C_CYA}========================================${C_RESET}"
    echo "${C_BOLD} Target: $URL${C_RESET}"
    echo "${C_BOLD}${C_CYA}========================================${C_RESET}"

    log "Obteniendo headers..."
    local HTTP_CODE CURL_OPTS
    if [ "$INSECURE" = "true" ]; then
        CURL_OPTS=(-skIL -A "$UA" --max-time 30 --connect-timeout 10 -o "$HEADERS_RAW" -w '%{http_code}')
    else
        CURL_OPTS=(-sIL -A "$UA" --max-time 30 --connect-timeout 10 -o "$HEADERS_RAW" -w '%{http_code}')
    fi
    HTTP_CODE="$(curl "${CURL_OPTS[@]}" "$URL" 2>/dev/null || echo "000")"

    if [ "$HTTP_CODE" = "000" ] || [ ! -s "$HEADERS_RAW" ]; then
        err "No se pudo conectar (HTTP $HTTP_CODE)"
        VERDICT_CODE=2; VERDICT_TXT="REVISAR MANUAL (sin respuesta)"
        return
    fi
    log "HTTP status final: $HTTP_CODE"

    extract_last_header_block "$HEADERS_RAW" > "$HEADERS"

    local SEC_HEADERS
    SEC_HEADERS="$(grep -iE \
        "^(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-embedder-policy|cross-origin-opener-policy|cross-origin-resource-policy|x-xss-protection|set-cookie):" \
        "$HEADERS" || true)"

    local ANALYSIS="" XFO CSP
    local has_protection=0 has_weak=0

    XFO="$(grep -i "^x-frame-options:" "$HEADERS" | tail -n1 || true)"
    CSP="$(grep -i "^content-security-policy:" "$HEADERS" | tail -n1 || true)"

    local CSP_FA=""
    if echo "$CSP" | grep -qi "frame-ancestors"; then
        CSP_FA="$(echo "$CSP" | grep -oiE "frame-ancestors[^;]*" | head -n1)"
    fi

    if [ -n "$CSP_FA" ]; then
        ANALYSIS+="[CSP] $CSP_FA"$'\n'
        if echo "$CSP_FA" | grep -qiE "'none'"; then
            ANALYSIS+="    -> Bloqueo total de framing (CSP gana sobre XFO)"$'\n'
            has_protection=1
        elif echo "$CSP_FA" | grep -qiE "'self'"; then
            ANALYSIS+="    -> Solo mismo origen (CSP gana sobre XFO)"$'\n'
            has_protection=1
        elif echo "$CSP_FA" | grep -qE "\*"; then
            ANALYSIS+="    -> ${C_RED}Wildcard: permite cualquier origen -> FRAMEABLE${C_RESET}"$'\n'
            has_weak=1
        else
            ANALYSIS+="    -> ${C_YEL}Allowlist de dominios: revisar si alguno es controlable${C_RESET}"$'\n'
            has_weak=1
        fi
    else
        ANALYSIS+="[CSP] Sin frame-ancestors"$'\n'
    fi

    if [ -n "$XFO" ]; then
        local XFO_VALUE
        XFO_VALUE="$(echo "$XFO" | cut -d: -f2- | xargs | tr '[:lower:]' '[:upper:]')"
        case "$XFO_VALUE" in
            DENY)
                ANALYSIS+="[XFO] DENY -> proteccion completa"$'\n'
                [ -z "$CSP_FA" ] && has_protection=1
                ;;
            SAMEORIGIN)
                ANALYSIS+="[XFO] SAMEORIGIN -> solo mismo origen"$'\n'
                [ -z "$CSP_FA" ] && has_protection=1
                ;;
            ALLOW-FROM*)
                ANALYSIS+="[XFO] ${C_YEL}ALLOW-FROM (deprecado, IGNORADO por navegadores modernos -> NO confiable)${C_RESET}"$'\n'
                has_weak=1
                ;;
            *)
                ANALYSIS+="[XFO] ${C_YEL}Valor no estandar: $XFO_VALUE${C_RESET}"$'\n'
                has_weak=1
                ;;
        esac
    else
        ANALYSIS+="[XFO] Ausente"$'\n'
    fi

    local COOKIES
    COOKIES="$(grep -i "^set-cookie:" "$HEADERS" || true)"
    if [ -n "$COOKIES" ]; then
        if echo "$COOKIES" | grep -qi "samesite"; then
            ANALYSIS+="[CK]  Cookies con SameSite"$'\n'
        else
            ANALYSIS+="[CK]  ${C_YEL}Cookies sin SameSite explicito${C_RESET}"$'\n'
        fi
    fi

    if [ "$has_protection" -eq 1 ] && [ "$has_weak" -eq 0 ]; then
        VERDICT_CODE=0; VERDICT_TXT="PROTEGIDO (segun headers)"
    elif [ "$has_protection" -eq 0 ] && [ -z "$CSP_FA" ] && [ -z "$XFO" ]; then
        VERDICT_CODE=1; VERDICT_TXT="VULNERABLE (sin XFO ni CSP frame-ancestors)"
    else
        VERDICT_CODE=2; VERDICT_TXT="REVISAR MANUAL (config debil o ambigua)"
    fi

    echo
    echo "$ANALYSIS"

    local SAFE_NAME HTML FAKE_HTML SEC_HTML ANALYSIS_HTML URL_ESC VERDICT_HTML
    SAFE_NAME="$(echo "$URL" | sed -E 's#https?://##; s#[^a-zA-Z0-9]#_#g' | cut -c1-60)"
    HTML="$OUTDIR/cj_${SAFE_NAME}.html"

    URL_ESC="$(printf '%s' "$URL" | html_escape)"
    SEC_HTML="$(printf '%s' "$SEC_HEADERS" | html_escape)"
    ANALYSIS_HTML="$(printf '%s' "$ANALYSIS" | sed 's/\x1b\[[0-9;]*m//g' | html_escape)"
    VERDICT_HTML="$(printf '%s' "$VERDICT_TXT" | html_escape)"

    if [ "$FAKE" = "true" ]; then
        FAKE_HTML='<div class="fake"><h3>Fake Attacker UI</h3><button>Confirmar</button></div>'
    else
        FAKE_HTML=""
    fi

    cat > "$HTML" <<EOF
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Clickjacking PoC - $URL_ESC</title>
<style>
body { margin:0; background:#111; color:#eee; font-family:Arial,sans-serif; }
.header { padding:15px; background:#222; border-bottom:3px solid #e33; }
.verdict { padding:10px 15px; font-weight:bold; }
iframe { width:100%; height:500px; border:3px solid #e33; }
.fake { position:absolute; top:120px; left:100px; z-index:10;
        background:rgba(255,0,0,.35); border:2px dashed yellow; padding:25px; }
.columns { display:flex; flex-wrap:wrap; }
.column { flex:1 1 400px; padding:15px; box-sizing:border-box; }
pre { background:#1a1a1a; padding:15px; white-space:pre-wrap; overflow:auto; border-radius:4px; }
</style>
</head>
<body>
<div class="header">
  <h2>Clickjacking Test</h2>
  Target: <b>$URL_ESC</b>
  <div class="verdict">Veredicto: $VERDICT_HTML</div>
</div>
<div style="position:relative">
  $FAKE_HTML
  <iframe src="$URL_ESC" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
</div>
<div class="columns">
  <div class="column">
    <h2>HTTP Security Headers</h2>
    <pre>$SEC_HTML</pre>
  </div>
  <div class="column">
    <h2>Clickjacking Analysis</h2>
    <pre>$ANALYSIS_HTML</pre>
  </div>
</div>
</body>
</html>
EOF

    log "PoC HTML: $HTML"

    if [ "$VERIFY" = "true" ]; then
        log "Verificacion dinamica de framing (chromium headless)..."
        local DYN
        DYN="$(verify_framing "$URL" "$HTML")"
        case "$DYN" in
            FRAMED)
                echo "    ${C_RED}-> El iframe CARGO contenido: clickjacking CONFIRMADO en runtime${C_RESET}"
                VERDICT_CODE=1; VERDICT_TXT="VULNERABLE (framing confirmado en runtime)"
                ;;
            BLOCKED)
                echo "    ${C_GRN}-> El navegador BLOQUEO el framing: protegido en runtime${C_RESET}"
                [ "$VERDICT_CODE" -ne 1 ] && { VERDICT_CODE=0; VERDICT_TXT="PROTEGIDO (framing bloqueado en runtime)"; }
                ;;
            *)
                warn "Verificacion dinamica no concluyente ($DYN)"
                ;;
        esac
    fi

    if [ "$SCREENSHOT" = "true" ]; then
        if command -v chromium >/dev/null 2>&1; then
            local IMG
            IMG="$OUTDIR/cj_${SAFE_NAME}.png"
            log "Captura..."
            chromium --headless --disable-gpu --no-sandbox \
                --window-size=1920,1200 --virtual-time-budget=5000 \
                --screenshot="$IMG" "file://$HTML" >/dev/null 2>&1 \
                && log "Imagen: $IMG" || warn "chromium fallo al capturar"
        else
            warn "chromium no encontrado, omitiendo screenshot"
        fi
    fi

    local VC="$C_YEL"
    [ "$VERDICT_CODE" -eq 0 ] && VC="$C_GRN"
    [ "$VERDICT_CODE" -eq 1 ] && VC="$C_RED"
    echo
    echo "${C_BOLD}VEREDICTO: ${VC}${VERDICT_TXT}${C_RESET}"

    echo "\"$URL\",$HTTP_CODE,$VERDICT_CODE,\"$VERDICT_TXT\"" >> "$OUTDIR/summary.csv"

    LAST_HTML="$HTML"
}

run_share() {
    local port="$1" target="$2"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        err "Puerto invalido: '$port'"
        return 1
    fi
    [ -e "$target" ] || { err "No existe: '$target'"; return 1; }

    command -v python3 >/dev/null 2>&1 || { err "python3 no instalado"; return 1; }

    if ! port_free "$port"; then
        err "El puerto $port esta ocupado o requiere permisos de root (<1024)"
        return 1
    fi

    local TMP SHARE_DIR RUTA_URL="/"
    TMP="$(mktemp -d)"
    register_tmpdir "$TMP"
    if [ -d "$target" ]; then
        SHARE_DIR="$(realpath "$target")"
        info "Compartiendo directorio: $SHARE_DIR"
    else
        local archivo base
        archivo="$(realpath "$target")"
        SHARE_DIR="$TMP/www"
        mkdir -p "$SHARE_DIR"
        ln -s "$archivo" "$SHARE_DIR/"
        base="$(basename "$archivo")"
        RUTA_URL="/$(url_encode "$base")"
        info "Compartiendo archivo: $archivo"
    fi

    local LOG_HTTP="$TMP/http.log"
    local LOG_NGROK="$TMP/ngrok.log"
    local PID_HTTP PID_NGROK=""

    _CLEANED=0
    cleanup_share() {
        [ "$_CLEANED" = "1" ] && return
        _CLEANED=1
        echo; info "Cerrando servidor y tunel..."
        [ -n "${PID_NGROK:-}" ] && kill "$PID_NGROK" 2>/dev/null || true
        [ -n "${PID_HTTP:-}" ] && kill "$PID_HTTP" 2>/dev/null || true
        wait 2>/dev/null || true
        ok "Todo cerrado."
    }
    trap cleanup_share INT TERM EXIT

    python3 -m http.server "$port" --bind 127.0.0.1 --directory "$SHARE_DIR" >"$LOG_HTTP" 2>&1 &
    PID_HTTP=$!
    register_pid "$PID_HTTP"
    sleep 1
    if ! kill -0 "$PID_HTTP" 2>/dev/null; then
        cat "$LOG_HTTP" >&2
        err "No se pudo iniciar http.server"
        return 1
    fi
    ok "Servidor local en http://127.0.0.1:${port}${RUTA_URL}"

    local PUBLIC_URL=""
    if [ "$LOCAL_ONLY" = "false" ]; then
        # Limpiar procesos ngrok huerfanos de ejecuciones anteriores (evita 404 por tunel viejo)
        pkill -f "ngrok http" 2>/dev/null || true
        sleep 0.5
        if ! command -v ngrok >/dev/null 2>&1; then
            warn "ngrok no instalado; solo URL local. Instala: https://ngrok.com/download"
        else
            ngrok http "$port" \
                --request-header-add "ngrok-skip-browser-warning: 1" \
                --log=stdout --log-format=logfmt >"$LOG_NGROK" 2>&1 &
            PID_NGROK=$!
            register_pid "$PID_NGROK"
            info "Levantando tunel ngrok..."
            local URL=""
            for _ in $(seq 1 40); do
                URL="$(grep -o 'url=https://[^ ]*' "$LOG_NGROK" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
                if [ -z "$URL" ] && command -v curl >/dev/null 2>&1; then
                    URL="$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null | python3 -c '
import sys, json
try:
    t = json.load(sys.stdin)["tunnels"]
    print(next(x["public_url"] for x in t if x["public_url"].startswith("https")))
except Exception:
    pass' 2>/dev/null || true)"
                fi
                [ -n "$URL" ] && break
                if ! kill -0 "$PID_NGROK" 2>/dev/null; then
                    echo; tail -n 15 "$LOG_NGROK" >&2
                    err "ngrok se cerro. Configura el token: ngrok config add-authtoken <TOKEN>"
                    return 1
                fi
                sleep 0.5
            done
            if [ -z "$URL" ]; then
                tail -n 15 "$LOG_NGROK" >&2
                err "No se obtuvo la URL de ngrok"
                return 1
            fi
            PUBLIC_URL="${URL}${RUTA_URL}"

            # Health check con el header para saltar el interstitial de ngrok
            if command -v curl >/dev/null 2>&1; then
                local HC
                HC="$(curl -sL -H "ngrok-skip-browser-warning: 1" -o /dev/null -w '%{http_code}' "$PUBLIC_URL" 2>/dev/null || echo "000")"
                if [ "$HC" = "200" ]; then
                    ok "Enlace publico verificado (HTTP 200)"
                else
                    warn "El enlace publico respondio HTTP $HC (revisa ngrok/archivo)"
                fi
            fi
        fi
    fi

    local FINAL_URL
    if [ -n "$PUBLIC_URL" ]; then
        FINAL_URL="$PUBLIC_URL"
    else
        FINAL_URL="http://127.0.0.1:${port}${RUTA_URL}"
    fi

    echo
    echo -e "${C_GRN}========================================${C_RESET}"
    echo -e "  ${C_BOLD}URL disponible:${C_RESET}"
    echo
    echo -e "  ${C_BOLD}${FINAL_URL}${C_RESET}"
    echo
    echo -e "${C_GRN}========================================${C_RESET}"

    if echo "$FINAL_URL" | grep -q "ngrok"; then
        warn "El aviso de ngrok (interstitial) se omite si el cliente envia el header 'ngrok-skip-browser-warning: 1' o usa un User-Agent no estandar."
        info "Con --open se abre chromium con User-Agent 'clickjackingrok/1.0' para saltarlo (o se descarga con el header)."
    fi

    if clipboard_copy "$FINAL_URL"; then
        ok "URL copiada al portapapeles"
    fi
    if [ "$QR" = "true" ]; then
        show_qr "$FINAL_URL"
    fi

    if [ "$OPEN_URL" = "true" ]; then
        local OPEN_TARGET="$FINAL_URL"
        if echo "$FINAL_URL" | grep -q "ngrok"; then
            # Chromium con User-Agent no estandar: ngrok no muestra el interstitial
            if command -v chromium >/dev/null 2>&1; then
                info "Abriendo con User-Agent no estandar para omitir el aviso de ngrok..."
                chromium --new-window --user-agent="clickjackingrok/1.0" "$FINAL_URL" >/dev/null 2>&1 &
                OPEN_TARGET=""
            else
                # Fallback: descargar con el header y abrir la copia local
                local TMPHTML
                TMPHTML="$(mktemp --suffix=.html)"
                register_tmpdir "$(dirname "$TMPHTML")"
                if curl -sL -H "ngrok-skip-browser-warning: 1" "$FINAL_URL" -o "$TMPHTML" 2>/dev/null && [ -s "$TMPHTML" ]; then
                    OPEN_TARGET="file://$TMPHTML"
                fi
            fi
        fi
        if [ -n "$OPEN_TARGET" ]; then
            if command -v firefox >/dev/null 2>&1; then
                firefox "$OPEN_TARGET" >/dev/null 2>&1 &
            elif command -v xdg-open >/dev/null 2>&1; then
                xdg-open "$OPEN_TARGET" >/dev/null 2>&1 &
            fi
        fi
    fi

    echo
    warn "Cualquiera con la URL puede acceder. Pulsa Ctrl+C para detener."
    info "Peticiones recibidas:"
    tail -n 0 -f "$LOG_HTTP" --pid="$PID_HTTP"
}

# ----------------------------------------------------------------------
# Parseo de argumentos
# ----------------------------------------------------------------------

if [ "${1:-}" = "serve" ] || [ "${1:-}" = "share" ]; then
    MODE="share"
    shift
    if [ $# -lt 2 ]; then
        err "Uso: $0 serve <puerto> <archivo|directorio>"
        usage 1
    fi
    SHARE_PORT="$1"; SHARE_TARGET="$2"; shift 2
fi

if [ "$MODE" = "share" ]; then
    while [ $# -gt 0 ]; do
        case "$1" in
            --local-only) LOCAL_ONLY="true" ;;
            --open) OPEN_URL="true" ;;
            --qr) QR="true" ;;
            --port) PORT="${2:-}"; shift ;;
            -h|--help) usage 0 ;;
            *) err "Opcion desconocida: $1"; usage 1 ;;
        esac
        shift
    done
    [ -n "$PORT" ] && SHARE_PORT="$PORT"
    show_banner
    run_share "$SHARE_PORT" "$SHARE_TARGET"
    exit $?
fi

[ $# -eq 0 ] && usage 1

while [ $# -gt 0 ]; do
    case "$1" in
        --fake-click) FAKE="true" ;;
        --screenshot) SCREENSHOT="true" ;;
        --verify)     VERIFY="true" ;;
        --serve)      SERVE="true" ;;
        --share)      SHARE="true" ;;
        --local-only) LOCAL_ONLY="true" ;;
        --open)       OPEN_URL="true" ;;
        --qr)         QR="true" ;;
        --insecure)   INSECURE="true" ;;
        --no-browser) NO_BROWSER="true" ;;
        --port)       PORT="${2:-}"; shift ;;
        --version)    echo "cj-ngrok.sh $VERSION"; exit 0 ;;
        -l)           LIST_FILE="${2:-}"; shift ;;
        -o)           OUTDIR="${2:-}"; shift ;;
        -h|--help)    usage 0 ;;
        -*)           err "Opcion desconocida: $1"; usage 1 ;;
        *)            TARGETS+=("$1") ;;
    esac
    shift
done

if [ -n "$LIST_FILE" ]; then
    [ -f "$LIST_FILE" ] || { err "No existe: $LIST_FILE"; exit 1; }
    while IFS= read -r line; do
        line="$(echo "$line" | xargs)"
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue
        TARGETS+=("$line")
    done < "$LIST_FILE"
fi

[ ${#TARGETS[@]} -eq 0 ] && { err "Sin targets."; usage 1; }

mkdir -p "$OUTDIR"

show_banner

echo "url,http_code,verdict_code,verdict" > "$OUTDIR/summary.csv"
LAST_HTML=""
GLOBAL_CODE=0

for t in "${TARGETS[@]}"; do
    analyze_target "$t"
    GLOBAL_CODE="$VERDICT_CODE"
done

log "Resumen: $OUTDIR/summary.csv"

if [ -n "$LAST_HTML" ]; then
    echo
    info "Ruta local del PoC: file://$LAST_HTML"
fi

if [ "$SHARE" = "true" ] || [ "$SERVE" = "true" ]; then
    if [ -z "$PORT" ]; then
        PORT="$(find_free_port 8000)" || { err "No se encontro puerto libre"; exit 1; }
    fi
    if [ "$SHARE" = "false" ]; then
        LOCAL_ONLY="true"
    fi
    # Compartir el PoC HTML generado, no toda la carpeta de salida
    if [ -n "$LAST_HTML" ] && [ -f "$LAST_HTML" ]; then
        run_share "$PORT" "$LAST_HTML"
    else
        run_share "$PORT" "$OUTDIR"
    fi
    exit $?
fi

if [ ${#TARGETS[@]} -eq 1 ] && [ "$NO_BROWSER" = "false" ] && [ -n "$LAST_HTML" ]; then
    if command -v firefox >/dev/null 2>&1; then
        firefox "$LAST_HTML" >/dev/null 2>&1 &
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$LAST_HTML" >/dev/null 2>&1 &
    fi
fi

exit "$GLOBAL_CODE"
