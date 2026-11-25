# clickjackingrok

> Ejecutable: `cj-ngrok.sh`

Herramienta en Bash que analiza la proteccion contra clickjacking de una URL,
genera un PoC HTML y permite servirlo localmente o compartirlo por Internet con
ngrok. Todo en un unico script autocontenido.

---

## Que hace

- Analiza la proteccion contra clickjacking:
  - `X-Frame-Options` (DENY / SAMEORIGIN / ALLOW-FROM)
  - `Content-Security-Policy: frame-ancestors` (tiene precedencia)
  - Cookies SameSite
- Genera un archivo **PoC HTML** por objetivo.
- Verifica el framing en tiempo de ejecucion con Chromium headless (`--verify`).
- Captura una captura de pantalla (`--screenshot`).
- Sirve **solo el PoC HTML** por HTTP local (`--serve`) o lo expone con ngrok
  (`--share`), mostrando la ruta local o la URL publica y copiandola al
  portapapeles (con `--qr`, tambien muestra un codigo QR).
- Al crear el tunel ngrok, agrega el header `ngrok-skip-browser-warning: 1` y
  verifica que el enlace publico responda `HTTP 200`.
- Con `--open`, abre el enlace en Chromium usando un User-Agent no estandar
  (`clickjackingrok/1.0`) para omitir el aviso de ngrok.
- Modo por lotes desde una lista de objetivos (`-l`).
- Codigos de salida utiles para CI: `0` PROTEGIDO, `1` VULNERABLE, `2` REVISAR MANUAL.

---

## Requisitos

Obligatorios:
- `bash` (>= 4)
- `curl`
- `python3`

Opcionales:
- `chromium` — capturas (`--screenshot`), verificacion dinamica (`--verify`) y
  apertura sin el aviso de ngrok (`--open`)
- `ngrok` — comparticion publica (`--share`)
- `firefox` o `xdg-open` — abrir la URL como alternativa a Chromium
- `qrencode` — codigo QR en la terminal (solo con `--qr`)
- `xclip` / `xsel` / `wl-copy` — copiar la URL al portapapeles

---

## Instalacion

### 1. Clonar el repositorio

```bash
git clone https://github.com/<tu-usuario>/clickjackingrok.git
cd clickjackingrok
chmod +x cj-ngrok.sh
```

### 2. Instalar dependencias

Debian / Ubuntu / Kali:
```bash
sudo apt update
sudo apt install -y bash curl python3 chromium
# opcionales
sudo apt install -y firefox-esr xclip qrencode
```

Arch Linux:
```bash
sudo pacman -S bash curl python chromium
# opcionales
sudo pacman -S firefox xclip qrencode
```

Fedora:
```bash
sudo dnf install bash curl python3 chromium
```

### 3. Instalar ngrok (para `--share`)

1. Descargar desde https://ngrok.com/download.
2. Crear una cuenta gratuita y obtener el authtoken.
3. Configurar:

```bash
ngrok config add-authtoken <TU_TOKEN>
```

Verificar:
```bash
ngrok version
```

> Sin ngrok, `--share` usa solo la URL local y muestra una advertencia.

---

## Inicio rapido

```bash
# Analisis simple (sin navegador)
./cj-ngrok.sh https://example.com --no-browser

# Verificacion dinamica (Chromium)
./cj-ngrok.sh https://example.com --verify --no-browser

# Generar PoC y servirlo localmente
./cj-ngrok.sh https://example.com --serve --no-browser

# Generar PoC y exponerlo publicamente con ngrok
./cj-ngrok.sh https://example.com --share --no-browser

# Generar PoC, exponerlo y abrirlo sin el aviso de ngrok
./cj-ngrok.sh https://example.com --share --open

# Compartir un archivo o directorio (modo compatible con server-ngrok)
./cj-ngrok.sh serve 8000 ./reporte.pdf
./cj-ngrok.sh serve 8080 ./carpeta_salida --local-only

# Por lotes desde una lista
./cj-ngrok.sh -l objetivos.txt --no-browser -o ./resultados
```

---

## Opciones

| Flag | Descripcion |
|------|-------------|
| `--fake-click` | Inyecta overlay falso en el PoC |
| `--screenshot` | Captura PNG del PoC |
| `--verify` | Verificacion dinamica de framing |
| `--serve` | Sirve solo el PoC HTML por HTTP local |
| `--share` | Sirve el PoC HTML y lo expone con ngrok |
| `--local-only` | Con `--share`, omite ngrok |
| `--port <n>` | Puerto para servir/compartir |
| `--open` | Abre la URL (Chromium con User-Agent no estandar si es ngrok) |
| `--qr` | Muestra un codigo QR de la URL (requiere `qrencode`) |
| `--insecure` | Desactiva verificacion TLS |
| `--no-browser` | No abre el navegador automaticamente |
| `-l <archivo>` | Archivo con una URL por linea |
| `-o <dir>` | Directorio de salida |
| `--version` | Imprime la version |
| `-h, --help` | Muestra la ayuda |

Codigos de salida (URL unica): `0` PROTEGIDO, `1` VULNERABLE, `2` REVISAR MANUAL.

---

## Aviso de ngrok (interstitial)

En el plan gratuito, ngrok muestra una pagina de aviso a los navegadores. El
script ya agrega el header `ngrok-skip-browser-warning: 1` al tunel y verifica
el enlace, pero el aviso depende del cliente. Opciones para omitirlo:

1. **User-Agent no estandar** (lo usa `--open`): Chromium con
   `--user-agent="clickjackingrok/1.0"`.
2. **Extension del navegador**: Requestly o ModHeader agregando el header
   `ngrok-skip-browser-warning: 1`.
3. **Proxy que agregue el header** (para compartir con terceros): por ejemplo un
   Cloudflare Worker que haga `fetch(url, { headers: { "ngrok-skip-browser-warning": "1" } })`.
4. **Otro tunel sin aviso**: `cloudflared tunnel --url http://127.0.0.1:PUERTO`.

---

## Notas de seguridad

- `--insecure` desactiva la verificacion TLS — usar solo en labs/CTF.
- En modo analisis, `--serve`/`--share` comparten **solo el PoC HTML**, no toda
  la carpeta `cj_out`.
- El subcomando `serve <puerto> <directorio>` si expone todo el contenido del
  directorio; revisa la ruta antes de usarlo.
- El PoC se guarda en `./cj_out` por defecto.
- Toda URL publica de ngrok es sensible: cualquiera con el enlace puede acceder.

---

## Salida

```
cj_out/
├── cj_<objetivo>.html      # PoC HTML
├── cj_<objetivo>.png       # captura (si --screenshot)
└── summary.csv             # url, http_code, verdict_code, verdict
```
