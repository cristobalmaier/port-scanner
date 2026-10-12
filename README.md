# netscope

Escáner de puertos **rápido y sencillo** en un solo archivo, sin dependencias
(solo la librería estándar de Python 3.10+). Pensado como alternativa ligera a
nmap para el reconocimiento rápido: encontrás puertos abiertos, el servicio y su
versión, y te marca los riesgos obvios.

```bash
netscope 192.168.1.10
```

> **Uso ético únicamente.** Escaneá solo sistemas tuyos o con autorización
> explícita por escrito.

---

## Requisitos

- Python 3.10 o superior
- Nada más. Cero dependencias.

---

## Instalación (para usar `netscope ip`)

Hacé el script ejecutable y enlazalo en tu PATH (una sola vez):

```bash
chmod +x netscope.py
mkdir -p ~/.local/bin
ln -sf "$PWD/netscope.py" ~/.local/bin/netscope
```

Listo. Ahora desde cualquier carpeta:

```bash
netscope 192.168.1.10
```

Si preferís no instalarlo:

```bash
python3 netscope.py 192.168.1.10
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
| `-t, --timeout` | Timeout por puerto en segundos (default: `0.7`) |
| `-T, --threads` | Conexiones simultáneas (default: `1000`) |
| `--no-banner` | No intentar leer banners/versiones |

### Ejemplos

```bash
# Puertos comunes + servicio/versión (por defecto)
netscope 192.168.1.10

# Rango concreto
netscope 192.168.1.10 -p 1-1024

# Todos los puertos (rápido: ~10s en localhost)
netscope 192.168.1.10 --full

# Por hostname
netscope scanme.nmap.org
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

- **Puertos abiertos** vía TCP connect scan asíncrono (no necesita root).
- **Servicio** por número de puerto (ssh, http, smb, redis, mongodb…).
- **Versión/banner** del servicio.
- **Riesgos obvios** en puertos peligrosos (Telnet, SMB, RDP, Redis, MongoDB,
  Docker API, Memcached, Elasticsearch…).

---

## Cómo funciona

Usa `asyncio`: mantiene cientos o miles de conexiones TCP en vuelo a la vez, por
eso es rápido. Es un *TCP connect scan* completo (no raw sockets), así que no
requiere permisos de administrador.

---

## Aviso legal

Herramienta para pruebas de seguridad autorizadas, laboratorios y educación.
Escanear sistemas sin permiso puede ser ilegal. Los autores no se hacen
responsables del mal uso.

---

## Licencia

MIT — ver [`LICENSE`](LICENSE).
