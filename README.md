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

Hace las dos fases de golpe —**descubrir todos los puertos** y **detectar
servicio/versión** de los abiertos—, te muestra una tabla fácil de leer y te
guarda los resultados para seguir con la auditoría.

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

## Cómo funciona (las 2 fases)

1. **Fase 1 — Descubrimiento.** Escanea los 65535 puertos TCP en paralelo con
   `asyncio` (equivalente a `nmap -p- --open --min-rate 5000`). No usa `ping`
   previo y no hace resolución inversa (como `-Pn -n`).
2. **Fase 2 — Servicio y versión.** Sobre los puertos abiertos pide el banner,
   la versión y, en HTTP/HTTPS, el título de la página y el certificado TLS
   (equivalente a `nmap -sCV`).

Al terminar, guarda en una carpeta:

- `allPorts.txt` — formato *grepable* (como `-oG allPorts`).
- `targeted.txt` — informe legible con servicios, versiones y riesgos (como
  `-oN targeted`).

---

## Opciones

| Opción | Descripción |
|--------|-------------|
| `-p, --ports` | Puertos concretos: `22,80,443` o `1-1000` |
| `--top N` | Solo los N puertos más comunes (más rápido) |
| `-t, --timeout` | Timeout por puerto en segundos (default `0.7`) |
| `-T, --threads` | Conexiones simultáneas (default `1000`) |
| `--no-version` | Solo descubrir puertos (saltar fase 2) |
| `-o, --output` | Carpeta de salida (default `netscope_<IP>/`) |
| `-q, --quiet` | Sin salida de progreso |

### Ejemplos

```bash
netscope 10.10.10.10                 # escaneo completo (recomendado)
netscope 10.10.10.10 --top 1000      # solo los 1000 más comunes
netscope 10.10.10.10 -p 22,80,443    # puertos concretos
netscope 10.10.10.10 -o audit/       # elegir carpeta de salida
netscope scanme.nmap.org             # host público de práctica (legal)
```

---

## Salida

```
  netscope — 10.10.10.10 (10.10.10.10)
  Fase 1/2 · descubriendo puertos abiertos (65535)...

  22/tcp open  (ssh)
  80/tcp open  (http)
  3306/tcp open  (mysql)

  [+] Abiertos: 22, 80, 3306  (3 en 8.4s)

  Fase 2/2 · detectando servicio/versión de 3 puertos...

  PUERTO      SERVICIO        VERSIÓN
  ──────────────────────────────────────────────────────────────
  22/tcp      ssh             OpenSSH 8.2p1
  80/tcp      http            Apache 2.4.7 — "Go ahead and ScanMe!"
  3306/tcp    mysql           MySQL 5.7.42
       [MEDIUM] MySQL expuesto en red

  Listo: 3 puertos abiertos en 9.1s
  Guardado en netscope_10_10_10_10/  (allPorts.txt, targeted.txt)
```

---

## Qué detecta

- **Puertos abiertos** (TCP connect scan asíncrono, sin root).
- **Servicio** por puerto y **versión/banner** del servicio.
- **HTTP/HTTPS**: título de la página, cabecera `Server` y datos del
  certificado TLS (versión, cifrado, CN, expiración).
- **Avisos de riesgo** en puertos peligrosos: Telnet, SMB, RDP, Redis, MongoDB,
  Docker API, Memcached, Elasticsearch, FTP, MySQL, PostgreSQL…

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
