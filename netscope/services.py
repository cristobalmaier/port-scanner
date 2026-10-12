"""Well-known service names, port categories and banner → service parsing.

Everything here is offline static data so the tool keeps working with no
network access to third-party databases.
"""

from __future__ import annotations

import re

# ── Well-known TCP/UDP port → service name ──────────────────────────────────
SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    26: "smtp", 37: "time", 43: "whois", 49: "tacacs", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 79: "finger", 80: "http",
    81: "http", 82: "http", 88: "kerberos", 102: "iso-tsap", 106: "pop3pw",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp", 194: "irc",
    199: "smux", 389: "ldap", 427: "svrloc", 443: "https", 444: "snpp",
    445: "microsoft-ds", 464: "kpasswd", 465: "smtps", 500: "isakmp",
    512: "exec", 513: "login", 514: "shell", 515: "printer", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi",
    631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync", 902: "vmware",
    990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis",
    1080: "socks", 1099: "rmi", 1110: "nfs", 1194: "openvpn",
    1433: "ms-sql", 1434: "ms-sql-m", 1521: "oracle", 1701: "l2tp",
    1720: "h323", 1723: "pptp", 1755: "ms-streaming", 1812: "radius",
    1883: "mqtt", 1900: "upnp", 2000: "cisco-sccp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2121: "ftp-proxy", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-tls", 2379: "etcd", 2401: "cvs", 2443: "https-alt",
    3000: "http-dev", 3128: "squid", 3260: "iscsi", 3268: "ldap-gc",
    3269: "ldap-gc-ssl", 3306: "mysql", 3389: "ms-wbt-server",
    3690: "svn", 4000: "http-alt", 4369: "epmd", 4444: "krb524",
    4505: "salt", 4506: "salt", 5000: "http-upnp", 5001: "http-alt",
    5009: "airport", 5060: "sip", 5061: "sips", 5222: "xmpp-client",
    5269: "xmpp-server", 5280: "xmpp-bosh", 5353: "mdns", 5357: "wsdapi",
    5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp",
    5683: "coap", 5900: "vnc", 5984: "couchdb", 5985: "winrm",
    5986: "winrm-ssl", 6000: "x11", 6001: "x11", 6379: "redis",
    6443: "kubernetes", 6667: "irc", 7001: "weblogic", 7002: "weblogic-ssl",
    7077: "spark", 7474: "neo4j", 7547: "cwmp", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp13", 8010: "http-alt", 8042: "http-alt",
    8069: "odoo", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
    8088: "http-alt", 8090: "http-alt", 8161: "activemq", 8180: "http-alt",
    8443: "https-alt", 8500: "consul", 8529: "arangodb", 8834: "nessus",
    8888: "http-alt", 8983: "solr", 9000: "cslistener", 9001: "tor-orport",
    9042: "cassandra", 9090: "http-alt", 9092: "kafka", 9100: "jetdirect",
    9160: "cassandra", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9443: "https-alt", 9999: "http-alt", 10000: "webmin",
    10050: "zabbix-agent", 10051: "zabbix-trapper", 10250: "kubelet",
    10255: "kubelet-ro", 11211: "memcache", 15672: "rabbitmq-mgmt",
    16379: "redis-alt", 25565: "minecraft", 27017: "mongodb",
    27018: "mongodb", 28017: "mongodb-web", 32768: "filenet-tms",
    50000: "sap", 50070: "hadoop-namenode", 61616: "activemq",
    49152: "unknown", 49153: "unknown",
}

# Ports the scanner treats as HTTP(S) for request-based fingerprinting.
HTTP_PORTS = {
    80, 81, 82, 88, 3000, 4000, 5000, 5001, 5601, 7070, 8000, 8008, 8010,
    8042, 8069, 8080, 8081, 8086, 8088, 8090, 8161, 8180, 8888, 8983, 9000,
    9090, 9200, 9999, 10000, 15672, 28017,
}
HTTPS_PORTS = {443, 8443, 9443, 2376, 5986, 6443, 7002, 8834, 9091, 10443}

# Coarse category, used to colour-code and to prioritise findings.
CATEGORY = {
    "web": {80, 81, 82, 443, 3000, 4000, 5000, 5001, 5601, 7001, 8000, 8008,
            8009, 8042, 8069, 8080, 8081, 8086, 8088, 8090, 8161, 8180, 8443,
            8500, 8529, 8834, 8888, 8983, 9000, 9090, 9200, 9300, 9443, 9999,
            10000, 10250, 10255, 15672, 27017, 28017, 50070},
    "database": {1433, 1434, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 9300,
                 11211, 27017, 27018},
    "remote": {22, 23, 3389, 5900, 5985, 5986, 6379, 512, 513, 514},
    "mail": {25, 110, 143, 465, 587, 993, 995, 26},
    "file": {21, 20, 69, 111, 139, 445, 2049, 873, 990},
    "infra": {53, 88, 123, 135, 137, 138, 161, 389, 636, 2181, 2375, 2376,
              2379, 4369, 5672, 6443, 9092, 10050, 10051, 61616},
}


def service_name(port: int, proto: str = "tcp") -> str:
    """Return the friendly service name for a port, or ``unknown``."""
    if proto == "udp":
        return UDP_SERVICE_NAMES.get(port, "unknown")
    return SERVICE_NAMES.get(port, "unknown")


UDP_SERVICE_NAMES: dict[int, str] = {
    53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp", 111: "rpcbind",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmp-trap", 500: "isakmp", 514: "syslog", 520: "route",
    623: "ipmi", 1900: "upnp", 2049: "nfs", 4500: "ipsec-nat-t",
    5353: "mdns", 5683: "coap",
}


def category(port: int) -> str:
    for name, ports in CATEGORY.items():
        if port in ports:
            return name
    return "other"


# ── Product/version extraction from raw banners ─────────────────────────────
# Each rule: (regex, product group name, version group name). Tested against
# the decoded banner text in order; the first match wins.
_PATTERNS = [
    (re.compile(r"SSH-\d+\.\d+-(?P<product>[A-Za-z][\w.\-]*?)[_/ ](?P<version>[\w.\-]+)", re.I),
     None),
    (re.compile(r"(?P<product>OpenSSH)[_/ ](?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r"\((?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla)[ ](?P<version>[\w.\-]+)\)", re.I), None),
    (re.compile(r"(?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP Service)[ /](?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r"(?P<product>nginx)/(?P<version>[\w.]+)", re.I), None),
    (re.compile(r"(?P<product>Apache)/(?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>Microsoft-IIS)/(?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>LiteSpeed)[/ ](?P<version>[\w.]+)", re.I), None),
    (re.compile(r"(?P<product>Postfix|Exim|Sendmail|Microsoft ESMTP|Exchange)[ /](?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r"(?P<product>Dovecot|Courier)[ /](?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r"redis_version:(?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r"STAT version (?P<version>[\w.\-]+)", re.I), None),
    (re.compile(r'"number"\s*:\s*"(?P<version>[\d.]+)"', re.I), None),
    (re.compile(r"(?P<product>MySQL|MariaDB)[ -]?(?P<version>\d[\w.\-]*)", re.I), None),
    (re.compile(r"(?P<product>Samba)[ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"RFB (?P<version>[\d.]+)", re.I), None),
    (re.compile(r"AMQP\x00(?:\x00|\x01)(?:\x09|\x08|\x07)(?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>Docker)[/ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>Jetty)[( ](?P<version>[\d.v]+)", re.I), None),
    (re.compile(r"(?P<product>Tomcat)[/ ]?(?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>gunicorn)[/ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>Werkzeug)[/ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>SimpleHTTP)[/ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>Python)[/ ](?P<version>[\d.]+)", re.I), None),
    (re.compile(r"(?P<product>socat\)|nc\)|netcat)", re.I), None),
]


def _printable_run(blob: bytes, min_len: int = 3) -> str:
    """Extract long printable/UTF-8 stretches from a binary blob."""
    text = blob.decode("utf-8", errors="replace")
    runs = re.findall(rf"[ -~]{{{min_len},}}", text)
    return " | ".join(runs[:8])


def parse_product_version(text: str) -> tuple[str, str]:
    """Best-effort ``(product, version)`` extraction from a banner string."""
    if not text:
        return "", ""
    for regex, _ in _PATTERNS:
        match = regex.search(text)
        if match:
            groups = match.groupdict()
            product = (groups.get("product") or "").strip()
            version = (groups.get("version") or "").strip()
            if product or version:
                return product, version
    return "", ""


def banner_to_text(raw: bytes) -> str:
    """Turn raw banner bytes into a compact single-line preview."""
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = _printable_run(raw)
    text = text.replace("\r", "").replace("\x00", " ")
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    return " ".join(lines)[:300]
