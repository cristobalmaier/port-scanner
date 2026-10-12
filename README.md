# netscope

Recon rápido de puertos **en un solo comando**, sin dependencias (solo la
librería estándar de Python 3.10+).

Reemplaza tu flujo de dos pasos de nmap:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn -vv <IP> -oG allPorts
nmap -sCV -p<PUERTOS> <IP> -oN targeted
```

por uno solo:

```bash
netscope <IP>
```

Hace todo de golpe —**descubrir todos los puertos**, **detectar
servicio/versión** y **confirmar vulnerabilidades típicas**—, te muestra una
tabla fácil de leer y te sugiere los próximos comandos para seguir la auditoría.

> ⚠️ **Uso ético únicamente.** Escaneá solo sistemas tuyos o con autorización
> explícita por escrito.

---

## Requisitos

- **Python 3.10 o superior**. Nada más.

---

## Clonar y usar

```bash
git clone https://github.com/tu-usuario/netscope.git
cd netscope
./netscope 10.10.10.10
```

Ya está: el script es ejecutable, no hace falta `pip` ni permisos de root.

¿Querés usar `netscope <ip>` desde cualquier carpeta? Corré el instalador:

```bash
./install.sh
netscope 10.10.10.10
```

En Windows: `python netscope 10.10.10.10`

---

## Cómo funciona

1. **Descubrimiento.** Escanea los 65535 puertos TCP en paralelo con `asyncio`
   (equivalente a `nmap -p- --open --min-rate 5000`). No usa `ping` previo y no
   hace resolución inversa (como `-Pn -n`).
2. **Servicio y versión.** Sobre los puertos abiertos pide el banner, la versión
   y, en HTTP/HTTPS, el título, las cabeceras y el certificado TLS (como
   `-sCV`).
3. **Chequeos activos.** Confirma vulnerabilidades típicas sin lanzar otra
   herramienta (ver más abajo).
4. **Próximos pasos.** Te sugiere los comandos listos para copiar (whatweb,
   gobuster, enum4linux, redis-cli, …) según lo que encontró.

No genera ningún archivo: todo sale por pantalla.

---

## Opciones

| Opción | Descripción |
|--------|-------------|
| `-p, --ports` | Puertos concretos: `22,80,443` o `1-1000` |
| `--top N` | Solo los N puertos más comunes (más rápido) |
| `-t, --timeout` | Timeout por puerto en segundos (default `0.7`) |
| `-T, --threads` | Conexiones simultáneas (default `1000`) |
| `--no-version` | Solo descubrir puertos (saltar servicio y chequeos) |
| `-q, --quiet` | Sin salida de progreso |

### Ejemplos

```bash
netscope 10.10.10.10                 # escaneo completo (recomendado)
netscope 10.10.10.10 --top 1000      # solo los 1000 más comunes
netscope 10.10.10.10 -p 22,80,443    # puertos concretos
netscope scanme.nmap.org             # host público de práctica (legal)
```

---

## Salida

```
  netscope — 10.10.10.10 (10.10.10.10)
  Fase 1/2 · descubriendo puertos abiertos (65535)...

  22/tcp open  (ssh)
  80/tcp open  (http)
  6379/tcp open  (redis)

  [+] Abiertos: 22, 80, 6379  (3 en 8.4s)

  Fase 2/2 · servicio/versión + chequeos activos de 3 puertos...

  PUERTO      SERVICIO        VERSIÓN
  ──────────────────────────────────────────────────────────────
  22/tcp      ssh             OpenSSH 8.2p1
  80/tcp      http            Apache 2.4.7 — "Go ahead and ScanMe!"
       [!] Faltan cabeceras de seguridad: CSP, X-Frame-Options, X-Content-Type-Options
  6379/tcp    redis
       [!] Redis SIN contraseña (responde PING)

  Listo: 3 puertos abiertos en 9.1s

  Próximos pasos sugeridos
  ──────────────────────────────────────────────────────────────
  22/tcp  ssh
      $ ssh <usuario>@10.10.10.10
      $ searchsploit OpenSSH
  80/tcp  http
      $ whatweb http://10.10.10.10
      $ gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt
      $ nikto -h http://10.10.10.10
  6379/tcp  redis
      $ redis-cli -h 10.10.10.10
```

---

## Qué detecta

- **Puertos abiertos** (TCP connect scan asíncrono, sin root).
- **Servicio** por puerto y **versión/banner** del servicio.
- **HTTP/HTTPS**: título de la página, cabeceras, cabecera `Server` y datos del
  certificado TLS (versión, cifrado, CN, expiración).
- **Avisos de riesgo** en puertos peligrosos: Telnet, SMB, RDP, Redis, MongoDB,
  Docker API, Memcached, Elasticsearch, FTP, MySQL, PostgreSQL…

## Chequeos activos (confirman, no solo avisan)

| Puerto | Qué comprueba |
|--------|---------------|
| 21 FTP | Login **anónimo** |
| 2375 Docker | API **expuesta** sin auth |
| 5900 VNC | **Sin autenticación** |
| 6379 Redis | **Sin contraseña** (responde `PING`) |
| 9200 Elasticsearch | Accesible **sin auth** |
| 27017 MongoDB | `listDatabases` **sin auth** |
| HTTP/HTTPS | Cabeceras de seguridad ausentes (CSP, X-Frame-Options, …) |

---

## Notas

- No necesita `sudo`: usa *TCP connect scan* (abre la conexión completa) en vez
  de SYN scan con raw sockets.
- Es más rápido en LAN que sobre Internet, donde los puertos **filtrados**
  (firewalls que no responden) dependen del `--timeout`.

---

## Aviso legal

Herramienta para pruebas de seguridad autorizadas, laboratorios y educación.
Escanear sistemas sin permiso puede ser ilegal. Los autores no se hacen
responsables del mal uso.

---

## Licencia

MIT — ver [`LICENSE`](LICENSE).
