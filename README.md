# 🔍 NETSCOPE — Port Scanner

```
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

Scanner de puertos escrito en Python puro. Detecta puertos abiertos, identifica servicios y alerta sobre configuraciones peligrosas — estilo nmap.

> **Uso ético únicamente.** Solo escanear redes o sistemas sobre los que tenés permiso explícito.

---

## Requisitos

- Python 3.6 o superior
- Sin dependencias externas — solo librería estándar

---

## ▶ Uso

```bash
python3 netscope.py <objetivo> [puerto_inicio] [puerto_fin]
```

### Ejemplos

```bash
# Escanear puertos 1-1024 en una IP local
python3 netscope.py 192.168.1.1

# Escanear un rango personalizado
python3 netscope.py 192.168.1.1 1 500

# Escanear un solo puerto
python3 netscope.py 192.168.1.1 80 80

# Escanear por hostname (servidor de prueba oficial de nmap)
python3 netscope.py scanme.nmap.org 1 1024
```

### Output esperado

```
  Nmap scan report for scanme.nmap.org (45.33.32.156)
  Host is up.
  Not shown: 1021 closed ports

  PORT        STATE   SERVICE
  ──────────────────────────────────────────────────
  22/tcp      open    ssh
  80/tcp      open    http
  3389/tcp    open    rdp
  |_ [HIGH] RDP — riesgo de fuerza bruta

  Netscope done: scanned in 4.21s — 3 open / 1024 total
```

---

## Sistema de colores

| Color | Significado |
|-------|-------------|
| 🟢 Verde | Servicios seguros (SSH, HTTPS, HTTP) |
| 🟡 Amarillo | Precaución (FTP, MySQL, PostgreSQL) |
| 🔴 Rojo | Riesgo alto (Telnet, SMB, RDP, Redis, MongoDB) |
| ⚪ Blanco | Servicio desconocido |

---

## Alertas de riesgo

Netscope muestra advertencias automáticas para los siguientes puertos:

| Puerto | Servicio | Nivel | Razón |
|--------|----------|-------|-------|
| 23 | Telnet | CRITICAL | Transmite contraseñas en texto plano |
| 445 | SMB | CRITICAL | Vulnerable a EternalBlue / ransomware |
| 6379 | Redis | CRITICAL | Sin autenticación por defecto |
| 27017 | MongoDB | CRITICAL | Sin autenticación por defecto |
| 3389 | RDP | HIGH | Expuesto a fuerza bruta |
| 5900 | VNC | HIGH | Autenticación débil |

---

## Cómo funciona

### 1. TCP Connect Scan
Netscope intenta establecer una conexión TCP completa con cada puerto usando `socket.connect_ex()`. Si la conexión es exitosa (retorna `0`), el puerto está **abierto**.

```python
sock.connect_ex((ip, port)) == 0  # True = puerto abierto
```

### 2. Escaneo paralelo con threads
En lugar de escanear puerto por puerto (lento), usa `ThreadPoolExecutor` para escanear hasta 200 puertos al mismo tiempo.

```python
with ThreadPoolExecutor(max_workers=200) as executor:
    futures = {executor.submit(scan_port, ip, p): p for p in ports}
```

### 3. Identificación de servicios
Cada puerto conocido está mapeado en el diccionario `SERVICES`. Si no está en la lista, muestra `unknown`.

---

## Estructura del proyecto

```
netscope/
│
├── netscope.py     # Script principal (único archivo)
└── README.md       # Este archivo
```

---

## Posibles mejoras (ideas para continuar)

- [ ] Exportar resultados a un archivo `.txt` o `.json`
- [ ] Agregar captura de banners para detectar versiones
- [ ] Escaneo UDP además de TCP
- [ ] Soporte para múltiples objetivos / rangos de red (CIDR)
- [ ] Integración con la API de Shodan

---

## Conceptos que este proyecto enseña

- Sockets y comunicación TCP/IP en Python
- Concurrencia con `threading` y `ThreadPoolExecutor`
- Reconocimiento de redes (fase 1 del pentesting)
- Identificación de servicios por número de puerto
- Uso de ANSI escape codes para colores en terminal

---

## Aviso legal

Este software es para uso educativo y pruebas en entornos autorizados. Escanear sistemas sin permiso puede ser ilegal según las leyes de tu país. El autor no se hace responsable del mal uso de esta herramienta.
