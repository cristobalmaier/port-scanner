# netscope

Escáner de puertos **rápido y sencillo** en un solo archivo, sin dependencias
(solo la librería estándar de Python 3.10+). Alternativa ligera a nmap para
reconocimiento rápido: te dice qué puertos están abiertos, qué servicio corre y
su versión, y marca los riesgos obvios.

```bash
netscope 192.168.1.10
```

> ⚠️ **Uso ético únicamente.** Escaneá solo sistemas tuyos o con autorización
> explícita por escrito.

---

## Requisitos

- **Python 3.10 o superior** (nada más).

No hay dependencias que instalar. En Linux/macOS suele venir ya instalado.

---

## Clonar y usar (2 pasos)

```bash
git clone https://github.com/tu-usuario/netscope.git
cd netscope
./netscope 192.168.1.10
```

Eso es todo. El script ya es ejecutable, no hace falta `pip` ni nada.

### ¿Querés usar `netscope <ip>` sin el `./` desde cualquier carpeta?

Corré el instalador incluido (crea un enlace en tu PATH, no copia archivos):

```bash
./install.sh
netscope 192.168.1.10
```

### En Windows

```powershell
python netscope 192.168.1.10
```

---

## Uso

```bash
netscope <objetivo> [opciones]
```

| Opción | Descripción |
|--------|-------------|
| `-p, --ports` | Puertos a escanear: `22,80,443` o `1-1000` |
| `--full` | Escanear los 65535 puertos TCP |
| `--top N` | Usar los N puertos más comunes (default: los 85 más habituales) |
| `-t, --timeout` | Timeout por puerto en segundos (default `0.7`) |
| `-T, --threads` | Conexiones simultáneas (default `1000`) |
| `--no-banner` | No intentar leer banners/versiones (más rápido) |

### Ejemplos

```bash
netscope 192.168.1.10                 # puertos comunes + servicio/versión
netscope 192.168.1.10 -p 1-1024       # un rango
netscope 192.168.1.10 --full          # los 65535 puertos (~10s en localhost)
netscope scanme.nmap.org              # por hostname
netscope 192.168.1.10 --no-banner     # más rápido, sin versiones
```

### Salida

```
  netscope — objetivo scanme.nmap.org (45.33.32.156)
  Escaneando 85 puertos TCP...

  PUERTO      ESTADO  SERVICIO      VERSION
  ────────────────────────────────────────────────────────────
  22/tcp      open    ssh           SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80/tcp      open    http          HTTP/1.1 200 OK
  3389/tcp    open    rdp
       [HIGH] RDP expuesto a fuerza bruta / BlueKeep

  Listo: 3 abiertos / 85 escaneados en 1.44s
```

---

## Qué detecta

- **Puertos abiertos** (TCP connect scan asíncrono, no necesita root).
- **Servicio** por número de puerto (ssh, http, smb, redis, mongodb…).
- **Versión/banner** del servicio.
- **Riesgos obvios**: Telnet, SMB, RDP, Redis, MongoDB, Docker API, Memcached,
  Elasticsearch, FTP, MySQL, PostgreSQL…

---

## Cómo funciona

Usa `asyncio` de Python: mantiene miles de conexiones TCP en vuelo a la vez, por
eso escanea en segundos. Es un *TCP connect scan* completo, así que funciona sin
permisos de administrador.

---

## Aviso legal

Herramienta para pruebas de seguridad autorizadas, laboratorios y educación.
Escanear sistemas sin permiso puede ser ilegal. Los autores no se hacen
responsables del mal uso.

---

## Licencia

MIT — ver [`LICENSE`](LICENSE).
