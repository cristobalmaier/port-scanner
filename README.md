<div align="center">

```
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**Escáner de puertos y reconocimiento de red ultrarrápido, sin dependencias.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## ¿Qué es Netscope?

Netscope es una herramienta de **reconocimiento de red** escrita en **Python puro
(cero dependencias)**. Hace las mismas tareas que suelen requerir una lista
interminable de flags de `nmap` —descubrimiento de puertos, detección de
servicios y versiones, fingerprint de TLS/HTTP y chequeos de seguridad activos—
con **un solo comando y decisiones por defecto inteligentes**.

```bash
netscope 192.168.1.10
```

Eso ya escanea los puertos más comunes, identifica los servicios, extrae
versiones y certificados TLS, analiza el HTTP y marca los riesgos encontrados.

> **Uso exclusivamente ético y autorizado.** Escaneá solo sistemas que poseas o
> para los que tengas permiso explícito por escrito.

---

## Índice

- [Características](#características)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Presets y ejemplos](#presets-y-ejemplos)
- [Formatos de salida](#formatos-de-salida)
- [¿Qué detecta exactamente?](#qué-detecta-exactamente)
- [Cómo funciona](#cómo-funciona)
- [Rendimiento](#rendimiento)
- [Comparativa con nmap](#comparativa-con-nmap)
- [Arquitectura del proyecto](#arquitectura-del-proyecto)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [Aviso legal](#aviso-legal)
- [Licencia](#licencia)

---

## Características

- ⚡ **Asíncrono y ultrarrápido** — miles de sockets en vuelo con `asyncio`
  (pipeline de dos fases: descubrimiento + enriquecimiento).
- 📦 **Cero dependencias** — solo la librería estándar de Python 3.10+.
- 🧠 **Defaults inteligentes** — `netscope <objetivo>` ya da recon completo.
- 🔎 **Detección de servicios y versiones** — banners, parser de producto/versión
  (OpenSSH, nginx, Apache, vsftpd, Redis, Elasticsearch…).
- 🔐 **Análisis TLS** — versión de protocolo, cifrado, ALPN (h2), emisor,
  titular y fecha de expiración del certificado.
- 🌐 **Fingerprint HTTP/HTTPS** — código de estado, título, cabeceras de
  seguridad ausentes y tecnologías (WordPress, Grafana, Jenkins, Tomcat…).
- 🛡️ **Chequeos activos no destructivos** — FTP anónimo, Redis sin contraseña,
  VNC sin auth, Memcached, Elasticsearch y APIs (Docker/etcd) expuestas.
- 🧬 **Base de CVEs offline** — cruza las versiones detectadas con
  vulnerabilidades conocidas (regreSSHion, backdoor de vsftpd, Apache 2.4.49…).
- 🌍 **Objetivos flexibles** — IP, hostname, `192.168.1.1-20` o `10.0.0.0/24`.
- 🧾 **Salidas para pipelines** — texto con color, JSON, XML y formato grep.
- 🚦 **Perfiles de sigilo** — de `paranoid` a `insane`, UDP y discovery opcional.

---

## Instalación

### Opción 1 — Sin instalación (recomendada)

Solo necesitás Python 3.10 o superior. No hay nada que instalar:

```bash
git clone https://github.com/tu-usuario/netscope.git
cd netscope
python3 -m netscope --help
```

### Opción 2 — Como comando del sistema

```bash
pip install -e .
netscope --help
```

---

## Uso rápido

```bash
# Recon inteligente sobre un host (recomendado)
netscope 192.168.1.10

# Toda una subred, puertos más comunes
netscope 192.168.1.0/24 --fast

# Los 65535 puertos TCP
netscope example.com --full

# Recon web (HTTP/HTTPS + tecnologías + cabeceras)
netscope 192.168.1.10 --web

# Rango de puertos personalizado
netscope 192.168.1.10 -p 22,80,1-1000

# UDP + chequeos activos completos
netscope 192.168.1.10 --deep --udp

# Escaneo silencioso (menos ruido para IDS)
netscope 192.168.1.10 --stealth

# Guardar el informe en JSON
netscope 192.168.1.10 -o informe.json
```

### Referencia de la CLI

| Flag | Descripción |
|------|-------------|
| `--fast` | Escaneo rápido (top 100 puertos) |
| `--full` | Los 65535 puertos TCP |
| `--web` | Solo puertos web + fingerprint HTTP |
| `--deep` | `--full` + UDP + todos los chequeos |
| `--stealth` | Bajo y lento (`-T1`, ideal contra IDS) |
| `-p, --ports SPEC` | `22,80,1-1000` · `top100` · `all` |
| `-T, --timing 0-5` | `paranoid … insane` (por defecto `4`) |
| `-c, --concurrency N` | Sockets simultáneos |
| `--timeout SEG` | Timeout por puerto |
| `-U, --udp` | Añadir sondeo UDP |
| `--discover` | Omitir hosts que no responden |
| `--no-version` / `--no-checks` / `--no-http` | Desactivar fases concretas |
| `--list-ports` | Mostrar qué puertos se escanearán y salir |
| `-o, --output FILE` | Guardar informe (formato por extensión) |
| `--format {text,json,xml,grep}` | Forzar formato de salida |
| `--save-all DIR` | Guardar `.txt`, `.json` y `.xml` a la vez |
| `-v, --verbose` | Mostrar banners y datos TLS |
| `-q, --quiet` / `--no-color` / `--no-banner` | Salida limpia |

---

## Presets y ejemplos

### Escaneo inteligente (por defecto)

```bash
$ netscope scanme.nmap.org -p 22,80,443
```

```
  45.33.32.156 (scanme.nmap.org)
  Host is up · conexión en 212.3 ms · OS: Linux (Ubuntu)

  PORT         STATE  SERVICE        VERSION
  ──────────────────────────────────────────────────────────────────
  22/tcp       open   ssh            OpenSSH 6.6.1p1
  80/tcp       open   http           Apache 2.4.7 — HTTP 200 "Go ahead and ScanMe!"
  443/tcp      open   https          — HTTP 200
    tls: TLSv1.3 · TLS_AES_256_GCM_SHA384 · CN=scanme.nmap.org · expira Aug 12 2027

  Hallazgos:
  [LOW] 80/tcp Cabeceras de seguridad ausentes
      Faltan: strict-transport-security, content-security-policy, ...
  [INFO] 80/tcp Servidor web
      Apache/2.4.7 (Ubuntu)

  Netscope done: 3 open ports on 1 host(s) · scanned in 2.33s
  Riesgos: LOW=1  INFO=1
```

### JSON para automatizar

```bash
netscope 10.0.0.0/24 --fast -o subred.json
```

Cada puerto incluye `service`, `product`, `version`, `banner`, `tls`, `http` y
una lista de `findings` con nivel `CRITICAL|HIGH|MEDIUM|LOW|INFO`.

---

## Formatos de salida

| Formato | Flag | Uso |
|---------|------|-----|
| Texto (color) | por defecto | Lectura humana en terminal |
| JSON | `--format json` / `-o x.json` | Pipelines, integraciones, informes |
| XML | `--format xml` / `-o x.xml` | Compatible en estilo con `nmap` |
| Grep | `--format grep` | `grep`/`awk`, importar a otras tools |

```bash
netscope host --save-all ./reporte     # genera .txt + .json + .xml
```

---

## ¿Qué detecta exactamente?

### 1. Descubrimiento de puertos
TCP connect scan asíncrono (no requiere privilegios de root) y sondeo UDP
best-effort para DNS, SNMP, NTP, NetBIOS, mDNS, etc.

### 2. Servicios y versiones
Parser de banners con patrones para `OpenSSH`, `nginx`, `Apache`, `Microsoft-IIS`,
`vsftpd`, `ProFTPD`, `Postfix`, `Exim`, `MySQL/MariaDB`, `Samba`, `Redis`,
`Memcached`, `Elasticsearch`, `VNC`, `Docker`, `Tomcat`, `Jetty` y más.

### 3. TLS
`ssl` de la stdlib: versión de protocolo, suite de cifrado, ALPN (`h2`),
certificado (emisor, titular, SAN, expiración) y alerta de protocolos débiles.

### 4. HTTP/HTTPS
Código de estado, título de la página, cabeceras de seguridad ausentes y
detección de tecnologías por firmas en el cuerpo y las cabeceras.

### 5. Chequeos activos (no destructivos)

| Puerto | Chequeo | Nivel |
|--------|---------|-------|
| 21 | Login FTP anónimo | CRITICAL |
| 6379 | Redis sin contraseña (`PING`) | CRITICAL |
| 5900 | VNC sin autenticación | CRITICAL |
| 11211 | Memcached sin auth (`stats`) | HIGH |
| 9200 | Elasticsearch sin auth | HIGH |
| 2375 | Docker API sin autenticación | CRITICAL |

### 6. Base de CVEs offline

Las versiones detectadas se cruzan con una base local de vulnerabilidades
conocidas. Ejemplos incluidos:

| Producto | Versión | CVE |
|----------|---------|-----|
| vsftpd | 2.3.4 | CVE-2011-2523 (backdoor) |
| OpenSSH | 8.5p1 – 9.7p1 | CVE-2024-6387 (regreSSHion) |
| Apache httpd | 2.4.49 / 2.4.50 | CVE-2021-41773 / CVE-2021-42013 |
| Exim | 4.87 – 4.91 | CVE-2019-10149 |
| Samba | 3.0.20 – 3.0.25 | CVE-2007-2447 |
| UnrealIRCd | 3.2.8.1 | CVE-2010-2075 |

> La base es **heurística** y sirve para priorizar: siempre confirmá un hallazgo
> manualmente antes de reportarlo.

---

## Cómo funciona

Netscope usa un **pipeline de dos fases** para ser rápido y a la vez profundo:

1. **Descubrimiento (asíncrono, masivo).** `asyncio` + `loop.sock_connect`
   mantienen miles de conexiones TCP en vuelo sin bloquear ni usar un hilo por
   puerto. Los puertos cerrados fallan al instante con `ConnectionRefused`, así
   que el coste lo marca el timeout de los puertos filtrados.

2. **Enriquecimiento (profundo, solo sobre puertos abiertos).** Como quedan
   pocos puertos abiertos, esta fase puede permitirse trabajo lento: banners,
   TLS, HTTP y chequeos activos. Se ejecuta en un pool de hilos para no bloquear
   el event loop.

Los hosts de una subred también se escanean en paralelo, por lo que un `/24`
completo termina en segundos.

```
CLI → parseo de objetivos/puertos → asyncio discovery → enriquecimiento → render
```

---

## Rendimiento

Medido con `--full -T5` (65535 puertos TCP), Python 3.14:

| Escenario | Tiempo |
|-----------|--------|
| `127.0.0.1` (loopback) | ~10 s |
| Subred LAN `/24` (top ports) | segundos |
| Host remoto (puertos comunes) | 2–3 s |

El tiempo depende sobre todo de la latencia y de los **puertos filtrados**
(firewalls que descartan paquetes silenciosamente): ahí manda el `--timeout`.

Consejos:
- LAN → `-T5` y `--timeout 0.5`.
- Internet → `-T4` (por defecto) y subir `--timeout` si ves muchos filtrados.
- Evitar IDS → `--stealth` (`-T1`, con delay).

---

## Comparativa con nmap

| | Netscope | nmap |
|---|:---:|:---:|
| Instalación | `git clone` (cero deps) | paquete del sistema |
| Complejidad de flags | mínima | alta |
| Descubrimiento TCP | ✅ connect scan | ✅ SYN/connect/ACK… |
| Detección de versiones | ✅ heurística | ✅ firma avanzada |
| TLS / HTTP recon | ✅ integrado | parcial (NSE) |
| Chequeos de seguridad | ✅ integrados | vía NSE |
| CVEs por versión | ✅ base offline | vía NSE/vulners |
| Salida JSON/XML/grep | ✅ | ✅ |
| SYN scan (raw sockets) | ❌ | ✅ (root) |
| OS fingerprinting por pila TCP | ❌ (heurística de banners) | ✅ |
| Scripts NSE (600+) | ❌ | ✅ |

**En una frase:** Netscope cubre con un solo comando la fase de *reconocimiento*
(cuando necesitás respuestas rápidas y poca ceremonia) y es un excelente
complemento de nmap, que sigue siendo superior para raw scanning, OS
fingerprinting y scripting avanzado.

---

## Arquitectura del proyecto

```
port-scanner/
├── netscope/
│   ├── __init__.py      # versión del paquete
│   ├── __main__.py      # python -m netscope
│   ├── cli.py           # argumentos, presets, banner
│   ├── scanner.py       # orquestación asíncrona (2 fases)
│   ├── target.py        # parseo de IP/CIDR/rangos y espec. de puertos
│   ├── banners.py       # banners, HTTP, TLS, chequeos activos
│   ├── tls.py           # metadatos y certificados TLS
│   ├── services.py      # puertos conocidos y parser de versiones
│   ├── vulns.py         # base de CVEs y riesgos estáticos
│   ├── models.py        # dataclasses del informe
│   ├── output.py        # render texto / JSON / XML / grep
│   └── constants.py     # colores, perfiles de timing, top-ports
├── tests/               # 32 tests (unittest, stdlib)
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

Cubren el parseo de objetivos y puertos, la extracción de versiones, la
comparación de versiones y el matching de CVEs, y los cuatro formatos de salida.

---

## Roadmap

- [ ] SYN scan opcional con raw sockets (requiere root)
- [ ] Fingerprinting de SO por pila TCP/IP
- [ ] Motor de scripts estilo NSE
- [ ] Exportación HTML de informes
- [ ] Modo "diff" entre dos escaneos
- [ ] Integración opcional con la API de Shodan

---

## Aviso legal

Netscope está pensado para **pruebas de seguridad autorizadas, laboratorios y
educación**. Escanear sistemas sin autorización explícita puede ser ilegal según
la legislación de tu país. Los autores no se responsabilizan del mal uso de esta
herramienta. Usala de forma ética.

---

## Licencia

Distribuido bajo la licencia **MIT**. Ver [`LICENSE`](LICENSE).
