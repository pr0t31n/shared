"""pr0t31n_repro — Reproduction command generator for findings.

Generates three reproduction approaches for a finding:
  1. tool_cmd    — the third-party tool command that identified it
  2. system_cmd  — a built-in OS/terminal command to verify
  3. python_script — a minimal Python script that reproduces it

Usage:
    from pr0t31n_repro import build_reproduction

    repro = build_reproduction(
        tool_cmd="nmap --script ssl-enum-ciphers -p 443 10.0.0.1",
        ip="10.0.0.1", port=443, protocol="https",
        finding_title="Weak SSL/TLS Cipher Suite",
        service="https",
    )
    # repro = {"tool_cmd": "...", "system_cmd": "...", "python_script": "..."}
"""
import shlex
import textwrap

_SYSTEM_CMD_TEMPLATES = {
    "ssh": "ssh -o PreferredAuthentications=none -o ConnectTimeout=5 -p {port} {ip} 2>&1",
    "ssl": "openssl s_client -connect {ip}:{port} -brief </dev/null 2>&1",
    "https": "curl -sk -o /dev/null -w '%{{http_code}}' https://{ip}:{port}/",
    "http": "curl -sk -o /dev/null -w '%{{http_code}}' http://{ip}:{port}/",
    "smb": "smbclient -L //{ip}/ -N -p {port} 2>&1",
    "ftp": "curl -s ftp://{ip}:{port}/ --connect-timeout 5 2>&1",
    "dns": "dig @{ip} -p {port} version.bind txt chaos +short 2>&1",
    "snmp": "snmpwalk -v2c -c public {ip}:{port} system 2>&1",
    "telnet": "echo '' | nc -w 5 {ip} {port} 2>&1",
    "rdp": "nc -zw 5 {ip} {port} && echo 'RDP port open' 2>&1",
    "mysql": "mysql -h {ip} -P {port} -u root --connect-timeout=5 -e 'SELECT VERSION();' 2>&1",
    "postgres": "psql -h {ip} -p {port} -U postgres -c 'SELECT version();' 2>&1",
    "mssql": "sqlcmd -S {ip},{port} -Q 'SELECT @@VERSION' -l 5 2>&1",
    "ldap": "ldapsearch -x -H ldap://{ip}:{port} -s base namingContexts 2>&1",
    "ntp": "ntpdate -q {ip} 2>&1",
    "smtp": "nc -w 5 {ip} {port} </dev/null 2>&1",
    "pop3": "nc -w 5 {ip} {port} </dev/null 2>&1",
    "imap": "nc -w 5 {ip} {port} </dev/null 2>&1",
    "vnc": "nc -zw 5 {ip} {port} && echo 'VNC port open' 2>&1",
    "hl7": "echo -e '\\x0bMSH|^~\\\\&|TEST||TEST||{ts}||QRY^A19|1|P|2.3\\x1c\\x0d' | nc -w 5 {ip} {port} 2>&1",
    "dicom": "echoscu {ip} {port} 2>&1",
    "modbus": "nc -w 5 {ip} {port} </dev/null 2>&1",
    "can": "candump {interface} -t a -n 100 2>&1",
    "bluetooth": "hcitool info {mac} 2>&1",
    "wifi": "iwlist {interface} scan 2>&1 | grep -A5 '{ssid}'",
    "zigbee": "zbdump -c {channel} -w /tmp/zbcap.pcap 2>&1",
    "usb": "lsusb -v -d {vid}:{pid} 2>&1",
    "serial": "stty -F {device} {baud} && cat {device}",
    "jtag": "openocd -f interface/{adapter}.cfg -f target/{target}.cfg -c 'init; halt; mdw 0x0 16; exit' 2>&1",
    "spi": "flashrom -p {programmer} -r /tmp/firmware.bin 2>&1",
}

_PYTHON_TEMPLATES = {
    "ssh": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        banner = s.recv(1024)
        print(f"SSH Banner: {{banner.decode().strip()}}")
        s.close()"""),
    "ssl": textwrap.dedent("""\
        import ssl, socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname="{ip}") as s:
            s.settimeout(5)
            s.connect(("{ip}", {port}))
            cert = s.getpeercert(binary_form=True)
            cipher = s.cipher()
            print(f"Cipher: {{cipher}}")
            print(f"Cert length: {{len(cert)}} bytes")"""),
    "https": textwrap.dedent("""\
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get("https://{ip}:{port}/", verify=False, timeout=5)
        print(f"Status: {{r.status_code}}")
        print(f"Headers: {{dict(r.headers)}}")"""),
    "http": textwrap.dedent("""\
        import requests
        r = requests.get("http://{ip}:{port}/", timeout=5)
        print(f"Status: {{r.status_code}}")
        print(f"Headers: {{dict(r.headers)}}")"""),
    "smb": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        # SMB negotiate request
        neg = (b"\\x00\\x00\\x00\\x2f"  # NetBIOS
               b"\\xff\\x53\\x4d\\x42"  # SMB magic
               b"\\x72"                  # Negotiate
               b"\\x00" * 27            # Flags/padding
               b"\\x00\\x02"            # Dialect count
               b"NT LM 0.12\\x00")
        s.send(neg)
        resp = s.recv(4096)
        print(f"SMB response: {{len(resp)}} bytes")
        s.close()"""),
    "ftp": textwrap.dedent("""\
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect("{ip}", {port}, timeout=5)
        banner = ftp.getwelcome()
        print(f"FTP Banner: {{banner}}")
        try:
            ftp.login("anonymous", "test@test.com")
            print("Anonymous login: ALLOWED")
        except ftplib.error_perm:
            print("Anonymous login: DENIED")
        ftp.quit()"""),
    "dns": textwrap.dedent("""\
        import socket
        import struct
        # DNS query for version.bind TXT CH
        txn = b"\\xaa\\xbb"
        flags = b"\\x01\\x00"
        q = b"\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
        name = b"\\x07version\\x04bind\\x00"
        qtype = b"\\x00\\x10"  # TXT
        qclass = b"\\x00\\x03"  # CH
        pkt = txn + flags + q + name + qtype + qclass
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(pkt, ("{ip}", {port}))
        data, _ = s.recvfrom(4096)
        print(f"DNS response: {{len(data)}} bytes")
        s.close()"""),
    "snmp": textwrap.dedent("""\
        import socket
        # SNMPv2c GET sysDescr.0 with community 'public'
        pkt = bytes.fromhex(
            "302902010104067075626c6963a01c0204"
            "00000001020100020100300e300c06082b"
            "060102010101000500"
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(pkt, ("{ip}", {port}))
        data, _ = s.recvfrom(4096)
        print(f"SNMP response: {{len(data)}} bytes")
        s.close()"""),
    "mysql": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        banner = s.recv(1024)
        if len(banner) > 4:
            version_end = banner.find(b"\\x00", 5)
            if version_end > 5:
                print(f"MySQL version: {{banner[5:version_end].decode()}}")
        s.close()"""),
    "telnet": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        banner = s.recv(1024)
        print(f"Banner: {{banner}}")
        s.close()"""),
    "ldap": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        # LDAP SearchRequest for rootDSE
        search = bytes.fromhex(
            "300c020101600702010304008000"
        )
        s.send(search)
        resp = s.recv(4096)
        print(f"LDAP response: {{len(resp)}} bytes")
        s.close()"""),
    "generic_tcp": textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect(("{ip}", {port}))
            print(f"Port {port} is OPEN on {ip}")
            s.send(b"\\r\\n")
            banner = s.recv(1024)
            if banner:
                print(f"Banner: {{banner[:200]}}")
        except (socket.timeout, ConnectionRefusedError) as e:
            print(f"Connection failed: {{e}}")
        finally:
            s.close()"""),
    "hl7": textwrap.dedent("""\
        import socket
        from datetime import datetime
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        msg = f"\\x0bMSH|^~\\\\&|TEST||TEST||{{ts}}||QRY^A19|1|P|2.3\\x1c\\x0d"
        s.send(msg.encode())
        resp = s.recv(4096)
        print(f"HL7 response: {{resp}}")
        s.close()"""),
    "dicom": textwrap.dedent("""\
        import socket, struct
        s = socket.socket()
        s.settimeout(5)
        s.connect(("{ip}", {port}))
        # DICOM A-ASSOCIATE-RQ (C-ECHO)
        # Minimal association request
        called_ae = b"ANY-SCP         "
        calling_ae = b"ECHOSCU         "
        pdu = b"\\x01\\x00" + b"\\x00" * 2 + b"\\x00\\x01" + b"\\x00" * 2
        pdu += called_ae + calling_ae + b"\\x00" * 32
        length = struct.pack(">I", len(pdu))
        s.send(b"\\x01\\x00" + length + pdu)
        resp = s.recv(4096)
        print(f"DICOM response type: 0x{{resp[0]:02x}} ({{len(resp)}} bytes)")
        s.close()"""),
}

_PORT_TO_PROTOCOL = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "rpc", 139: "smb",
    143: "imap", 161: "snmp", 162: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtp", 587: "smtp", 636: "ldap", 993: "imap",
    995: "pop3", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2575: "hl7", 3306: "mysql", 3389: "rdp", 4242: "dicom",
    5432: "postgres", 5900: "vnc", 5901: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 8888: "http", 9100: "printer",
    11211: "memcached", 27017: "mongodb", 502: "modbus",
    104: "dicom",
}


def _resolve_protocol(protocol, port, service):
    if protocol:
        return protocol.lower().replace("tls", "ssl").replace("tcp", "")
    if service:
        svc = service.lower()
        if svc in _SYSTEM_CMD_TEMPLATES:
            return svc
        for key in ("ssh", "http", "https", "smb", "ftp", "dns", "snmp",
                     "mysql", "postgres", "mssql", "ldap", "smtp", "hl7",
                     "dicom", "modbus", "vnc", "rdp", "telnet"):
            if key in svc:
                return key
    if port and int(port) in _PORT_TO_PROTOCOL:
        return _PORT_TO_PROTOCOL[int(port)]
    return ""


def build_reproduction(tool_cmd="", ip="", port=0, protocol="",
                       service="", finding_title="", hostname="",
                       mac="", ssid="", interface="", channel=0,
                       vid="", pid="", device="", baud=115200,
                       adapter="", target="", programmer="",
                       url="", extra_params=None):
    """Build a reproduction dict for a finding.

    Returns {"tool_cmd": str, "system_cmd": str, "python_script": str}.
    All three are best-effort — empty string if no template matches.
    """
    proto = _resolve_protocol(protocol, port, service)
    port = int(port) if port else 0

    fmt_vars = {
        "ip": ip or hostname or "TARGET",
        "port": port or 0,
        "hostname": hostname or ip or "TARGET",
        "mac": mac or "AA:BB:CC:DD:EE:FF",
        "ssid": ssid or "TARGET_SSID",
        "interface": interface or "eth0",
        "channel": channel or 11,
        "vid": vid or "0000",
        "pid": pid or "0000",
        "device": device or "/dev/ttyUSB0",
        "baud": baud,
        "adapter": adapter or "jlink",
        "target": target or "stm32f4x",
        "programmer": programmer or "ch341a_spi",
        "url": url or "",
        "ts": "20260101120000",
    }

    # tool_cmd: use what was passed (the actual command that found it)
    result_tool_cmd = tool_cmd or ""

    # system_cmd: look up by protocol
    sys_template = _SYSTEM_CMD_TEMPLATES.get(proto, "")
    if not sys_template and port:
        sys_template = "nc -zw 5 {ip} {port} && echo 'Port {port} open' 2>&1"
    result_system_cmd = ""
    if sys_template:
        try:
            result_system_cmd = sys_template.format(**fmt_vars)
        except (KeyError, IndexError):
            result_system_cmd = sys_template

    # python_script: look up by protocol
    py_template = _PYTHON_TEMPLATES.get(proto, "")
    if not py_template and port:
        py_template = _PYTHON_TEMPLATES.get("generic_tcp", "")
    result_python = ""
    if py_template:
        try:
            result_python = py_template.format(**fmt_vars)
        except (KeyError, IndexError):
            result_python = py_template

    return {
        "tool_cmd": result_tool_cmd,
        "system_cmd": result_system_cmd,
        "python_script": result_python,
    }


def merge_reproduction(finding_dict, repro_dict):
    """Merge reproduction commands into a finding dict (in-place).

    Preserves existing 'command' field. Adds the nested 'reproduction' key
    AND the flat top-level fields (repro_tool, repro_cli, repro_python) so
    the __CRUCIBLE_FINDING__ token carries them for the Crucible DB / UI.
    """
    if not repro_dict:
        return finding_dict
    # If tool_cmd is empty but command exists, use command
    if not repro_dict.get("tool_cmd") and finding_dict.get("command"):
        repro_dict["tool_cmd"] = finding_dict["command"]
    finding_dict["reproduction"] = repro_dict
    # Flat top-level fields for Crucible token → DB → UI flow
    finding_dict["repro_tool"]   = repro_dict.get("tool_cmd", "")
    finding_dict["repro_cli"]    = repro_dict.get("system_cmd", "")
    finding_dict["repro_python"] = repro_dict.get("python_script", "")
    return finding_dict
