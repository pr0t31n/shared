#!/usr/bin/env python3
"""pr0t31n_default_creds — default credential database for known software/services.

Structured lookup of factory-default credentials by software name, service
name, or port number.  Designed for use by Fracture (web apps), Siphon (APIs),
Scattershot3 (network services), and Auger (databases) during authenticated
testing phases.

Standalone CLI:
    python3 pr0t31n_default_creds.py --lookup tomcat
    python3 pr0t31n_default_creds.py --port 3306
    python3 pr0t31n_default_creds.py --search apache
    python3 pr0t31n_default_creds.py --category database
    python3 pr0t31n_default_creds.py --dump  # all entries as JSON
    python3 pr0t31n_default_creds.py --export-pairs tomcat -o creds.txt

Library:
    import pr0t31n_default_creds as dc
    creds = dc.get_creds("tomcat")        # [Credential(user, password, ...)]
    creds = dc.get_creds_by_port(3306)    # all software on that port
    creds = dc.search("apache")           # fuzzy name search
    pairs = dc.get_pairs("tomcat")        # [("tomcat","tomcat"), ...]
"""

VERSION = "1.0.0"

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class Credential:
    username: str
    password: str
    note: str = ""

@dataclass
class SoftwareEntry:
    name: str
    aliases: List[str] = field(default_factory=list)
    category: str = ""
    default_ports: List[int] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)

    def pairs(self) -> List[Tuple[str, str]]:
        return [(c.username, c.password) for c in self.credentials]


# ── Database ─────────────────────────────────────────────────────────────────

def _c(u, p, n=""):
    return Credential(u, p, n)

_DATABASE: List[SoftwareEntry] = [

    # ── Web Servers & Application Servers ─────────────────────────────────

    SoftwareEntry(
        name="tomcat",
        aliases=["apache tomcat", "tomcat manager", "catalina"],
        category="web_server",
        default_ports=[8080, 8443, 8005, 8009],
        protocols=["http", "https"],
        credentials=[
            _c("tomcat", "tomcat"),
            _c("admin", "admin"),
            _c("admin", ""),
            _c("admin", "password"),
            _c("manager", "manager"),
            _c("role1", "role1"),
            _c("root", "root"),
            _c("tomcat", "s3cret"),
            _c("both", "tomcat"),
            _c("admin", "tomcat"),
            _c("tomcat", "changethis"),
        ],
    ),
    SoftwareEntry(
        name="jenkins",
        aliases=["jenkins ci", "jenkins server"],
        category="ci_cd",
        default_ports=[8080, 8443, 50000],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("admin", "jenkins"),
            _c("admin", ""),
            _c("jenkins", "jenkins"),
        ],
    ),
    SoftwareEntry(
        name="jboss",
        aliases=["jboss as", "wildfly", "jboss eap", "red hat jboss"],
        category="web_server",
        default_ports=[8080, 9990, 4848],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", ""),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="weblogic",
        aliases=["oracle weblogic", "weblogic server", "wls"],
        category="web_server",
        default_ports=[7001, 7002, 9002],
        protocols=["http", "https", "t3"],
        credentials=[
            _c("weblogic", "weblogic"),
            _c("weblogic", "weblogic1"),
            _c("weblogic", "welcome1"),
            _c("weblogic", "password"),
            _c("system", "password"),
            _c("operator", "password"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="glassfish",
        aliases=["oracle glassfish", "glassfish server", "payara"],
        category="web_server",
        default_ports=[4848, 8080, 8181],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", ""),
            _c("admin", "adminadmin"),
        ],
    ),
    SoftwareEntry(
        name="nginx",
        aliases=["nginx server", "nginx plus"],
        category="web_server",
        default_ports=[80, 443, 8080],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", ""),
        ],
    ),
    SoftwareEntry(
        name="iis",
        aliases=["microsoft iis", "internet information services"],
        category="web_server",
        default_ports=[80, 443, 8080],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("administrator", ""),
            _c("administrator", "password"),
        ],
    ),

    # ── CMS & Web Applications ───────────────────────────────────────────

    SoftwareEntry(
        name="wordpress",
        aliases=["wp", "wp-admin", "wp-login"],
        category="cms",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("admin", "Password1"),
            _c("administrator", "administrator"),
            _c("user", "user"),
            _c("wordpress", "wordpress"),
            _c("admin", "wordpress"),
        ],
    ),
    SoftwareEntry(
        name="joomla",
        aliases=["joomla cms", "joomla!"],
        category="cms",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("admin", "joomla"),
        ],
    ),
    SoftwareEntry(
        name="drupal",
        aliases=["drupal cms"],
        category="cms",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("admin", "drupal"),
        ],
    ),
    SoftwareEntry(
        name="magento",
        aliases=["adobe commerce", "magento commerce"],
        category="cms",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin123"),
            _c("admin", "magento"),
            _c("admin", "123123"),
        ],
    ),
    SoftwareEntry(
        name="phpmyadmin",
        aliases=["pma", "php my admin"],
        category="admin_panel",
        default_ports=[80, 443, 8080],
        protocols=["http", "https"],
        credentials=[
            _c("root", ""),
            _c("root", "root"),
            _c("root", "password"),
            _c("root", "mysql"),
            _c("admin", "admin"),
            _c("pma", ""),
            _c("mysql", "mysql"),
        ],
    ),
    SoftwareEntry(
        name="grafana",
        aliases=["grafana server", "grafana oss"],
        category="monitoring",
        default_ports=[3000],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "grafana"),
        ],
    ),
    SoftwareEntry(
        name="kibana",
        aliases=["elastic kibana"],
        category="monitoring",
        default_ports=[5601],
        protocols=["http", "https"],
        credentials=[
            _c("elastic", "changeme"),
            _c("elastic", "elastic"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="nagios",
        aliases=["nagios xi", "nagios core"],
        category="monitoring",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("nagiosadmin", "nagiosadmin"),
            _c("nagiosadmin", "nagios"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="zabbix",
        aliases=["zabbix server", "zabbix frontend"],
        category="monitoring",
        default_ports=[80, 443, 10051],
        protocols=["http", "https"],
        credentials=[
            _c("Admin", "zabbix"),
            _c("admin", "zabbix"),
            _c("guest", ""),
        ],
    ),
    SoftwareEntry(
        name="gitlab",
        aliases=["gitlab ce", "gitlab ee"],
        category="ci_cd",
        default_ports=[80, 443, 8080],
        protocols=["http", "https"],
        credentials=[
            _c("root", "5iveL!fe"),
            _c("admin", "5iveL!fe"),
            _c("root", "password"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="sonarqube",
        aliases=["sonar", "sonarqube server"],
        category="ci_cd",
        default_ports=[9000],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="nexus",
        aliases=["nexus repository", "sonatype nexus"],
        category="ci_cd",
        default_ports=[8081],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin123"),
        ],
    ),
    SoftwareEntry(
        name="portainer",
        aliases=["portainer ce", "portainer server"],
        category="container",
        default_ports=[9000, 9443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="rancher",
        aliases=["rancher server"],
        category="container",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="airflow",
        aliases=["apache airflow"],
        category="ci_cd",
        default_ports=[8080],
        protocols=["http", "https"],
        credentials=[
            _c("airflow", "airflow"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="minio",
        aliases=["minio server", "minio console"],
        category="storage",
        default_ports=[9000, 9001],
        protocols=["http", "https"],
        credentials=[
            _c("minioadmin", "minioadmin"),
            _c("admin", "admin"),
            _c("minio", "minio123"),
        ],
    ),
    SoftwareEntry(
        name="rabbitmq",
        aliases=["rabbitmq management", "rabbitmq server"],
        category="messaging",
        default_ports=[15672, 5672, 5671, 25672],
        protocols=["http", "https", "amqp"],
        credentials=[
            _c("guest", "guest"),
            _c("admin", "admin"),
            _c("rabbitmq", "rabbitmq"),
        ],
    ),
    SoftwareEntry(
        name="activemq",
        aliases=["apache activemq"],
        category="messaging",
        default_ports=[8161, 61616],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("user", "password"),
        ],
    ),
    SoftwareEntry(
        name="solr",
        aliases=["apache solr"],
        category="search",
        default_ports=[8983],
        protocols=["http", "https"],
        credentials=[
            _c("solr", "SolrRocks"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="confluence",
        aliases=["atlassian confluence"],
        category="wiki",
        default_ports=[8090, 8091],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "confluence"),
        ],
    ),
    SoftwareEntry(
        name="jira",
        aliases=["atlassian jira", "jira server"],
        category="project_mgmt",
        default_ports=[8080, 8443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "jira"),
        ],
    ),
    SoftwareEntry(
        name="bitbucket",
        aliases=["atlassian bitbucket", "bitbucket server"],
        category="ci_cd",
        default_ports=[7990, 7999],
        protocols=["http", "https", "ssh"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),

    # ── Databases ────────────────────────────────────────────────────────

    SoftwareEntry(
        name="mysql",
        aliases=["mariadb", "percona", "mysql server", "mariadb server"],
        category="database",
        default_ports=[3306],
        protocols=["mysql"],
        credentials=[
            _c("root", ""),
            _c("root", "root"),
            _c("root", "password"),
            _c("root", "mysql"),
            _c("root", "toor"),
            _c("root", "123456"),
            _c("mysql", "mysql"),
            _c("admin", "admin"),
            _c("dbadmin", "dbadmin"),
            _c("test", "test"),
            _c("user", "user"),
        ],
    ),
    SoftwareEntry(
        name="postgresql",
        aliases=["postgres", "pg", "postgresql server", "psql"],
        category="database",
        default_ports=[5432],
        protocols=["postgresql"],
        credentials=[
            _c("postgres", "postgres"),
            _c("postgres", ""),
            _c("postgres", "password"),
            _c("postgres", "admin"),
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="mssql",
        aliases=["microsoft sql server", "sql server", "ms-sql", "sqlserver"],
        category="database",
        default_ports=[1433, 1434],
        protocols=["tds", "mssql"],
        credentials=[
            _c("sa", ""),
            _c("sa", "sa"),
            _c("sa", "password"),
            _c("sa", "Password1"),
            _c("sa", "Password123"),
            _c("sa", "sql"),
            _c("sa", "sqlserver"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="oracle",
        aliases=["oracle db", "oracle database", "oracle xe", "oracle express"],
        category="database",
        default_ports=[1521, 1630],
        protocols=["oracle", "tns"],
        credentials=[
            _c("system", "oracle"),
            _c("system", "manager"),
            _c("system", "password"),
            _c("sys", "change_on_install"),
            _c("sys", "oracle"),
            _c("scott", "tiger"),
            _c("dbsnmp", "dbsnmp"),
            _c("hr", "hr"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="mongodb",
        aliases=["mongo", "mongod", "mongodb server"],
        category="database",
        default_ports=[27017, 27018, 27019, 28017],
        protocols=["mongodb"],
        credentials=[
            _c("admin", ""),
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("root", "root"),
            _c("mongo", "mongo"),
        ],
    ),
    SoftwareEntry(
        name="redis",
        aliases=["redis server", "redis-server"],
        category="database",
        default_ports=[6379],
        protocols=["redis"],
        credentials=[
            _c("", ""),
            _c("", "redis"),
            _c("", "password"),
            _c("default", ""),
            _c("default", "redis"),
        ],
    ),
    SoftwareEntry(
        name="couchdb",
        aliases=["apache couchdb"],
        category="database",
        default_ports=[5984, 6984],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "password"),
            _c("admin", "admin"),
            _c("couchdb", "couchdb"),
        ],
    ),
    SoftwareEntry(
        name="cassandra",
        aliases=["apache cassandra", "datastax cassandra"],
        category="database",
        default_ports=[9042, 9160],
        protocols=["cql"],
        credentials=[
            _c("cassandra", "cassandra"),
        ],
    ),
    SoftwareEntry(
        name="elasticsearch",
        aliases=["elastic", "elasticsearch server", "es"],
        category="database",
        default_ports=[9200, 9300],
        protocols=["http", "https"],
        credentials=[
            _c("elastic", "changeme"),
            _c("elastic", "elastic"),
            _c("admin", "admin"),
            _c("", ""),
        ],
    ),
    SoftwareEntry(
        name="influxdb",
        aliases=["influx", "influxdb server"],
        category="database",
        default_ports=[8086, 8088],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("root", "root"),
        ],
    ),
    SoftwareEntry(
        name="memcached",
        aliases=["memcache"],
        category="database",
        default_ports=[11211],
        protocols=["memcached"],
        credentials=[
            _c("", "", "typically no auth"),
        ],
    ),

    # ── Network Equipment ────────────────────────────────────────────────

    SoftwareEntry(
        name="cisco",
        aliases=["cisco ios", "cisco switch", "cisco router", "cisco asa",
                 "cisco catalyst", "cisco nexus"],
        category="network",
        default_ports=[22, 23, 80, 443],
        protocols=["ssh", "telnet", "http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "cisco"),
            _c("admin", ""),
            _c("cisco", "cisco"),
            _c("enable", "cisco"),
            _c("root", "cisco"),
            _c("", "cisco"),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="mikrotik",
        aliases=["mikrotik routeros", "routeros", "mikrotik router"],
        category="network",
        default_ports=[22, 23, 80, 443, 8291, 8728, 8729],
        protocols=["ssh", "telnet", "http", "https", "winbox", "api"],
        credentials=[
            _c("admin", ""),
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="juniper",
        aliases=["juniper junos", "junos", "juniper srx", "juniper ex",
                 "juniper mx"],
        category="network",
        default_ports=[22, 23, 80, 443],
        protocols=["ssh", "telnet", "http", "https"],
        credentials=[
            _c("root", ""),
            _c("root", "juniper"),
            _c("admin", "juniper"),
            _c("super", "juniper"),
        ],
    ),
    SoftwareEntry(
        name="fortinet",
        aliases=["fortigate", "fortios", "fortigate firewall", "forti"],
        category="network",
        default_ports=[22, 23, 80, 443],
        protocols=["ssh", "telnet", "http", "https"],
        credentials=[
            _c("admin", ""),
            _c("admin", "admin"),
            _c("admin", "fortinet"),
        ],
    ),
    SoftwareEntry(
        name="paloalto",
        aliases=["palo alto", "pan-os", "panos", "palo alto firewall"],
        category="network",
        default_ports=[22, 443],
        protocols=["ssh", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "paloalto"),
        ],
    ),
    SoftwareEntry(
        name="ubiquiti",
        aliases=["unifi", "ubiquiti unifi", "edgeos", "edgerouter",
                 "unifi controller", "ubnt"],
        category="network",
        default_ports=[22, 80, 443, 8443, 8080],
        protocols=["ssh", "http", "https"],
        credentials=[
            _c("ubnt", "ubnt"),
            _c("admin", ""),
            _c("admin", "admin"),
            _c("root", "ubnt"),
        ],
    ),
    SoftwareEntry(
        name="aruba",
        aliases=["aruba networks", "hpe aruba", "aruba controller",
                 "aruba instant"],
        category="network",
        default_ports=[22, 80, 443, 4343],
        protocols=["ssh", "http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", ""),
        ],
    ),
    SoftwareEntry(
        name="netgear",
        aliases=["netgear router", "netgear switch", "netgear prosafe"],
        category="network",
        default_ports=[22, 23, 80, 443],
        protocols=["ssh", "telnet", "http", "https"],
        credentials=[
            _c("admin", "password"),
            _c("admin", "admin"),
            _c("admin", "1234"),
            _c("admin", ""),
        ],
    ),
    SoftwareEntry(
        name="tp-link",
        aliases=["tplink", "tp link", "tp-link router"],
        category="network",
        default_ports=[22, 23, 80, 443],
        protocols=["ssh", "telnet", "http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="dlink",
        aliases=["d-link", "d link", "dlink router"],
        category="network",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", ""),
            _c("admin", "password"),
            _c("user", "user"),
        ],
    ),
    SoftwareEntry(
        name="sonicwall",
        aliases=["sonicwall firewall", "dell sonicwall"],
        category="network",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "password"),
        ],
    ),

    # ── Remote Access & Management ───────────────────────────────────────

    SoftwareEntry(
        name="ssh",
        aliases=["openssh", "ssh server", "sshd", "dropbear"],
        category="remote_access",
        default_ports=[22],
        protocols=["ssh"],
        credentials=[
            _c("root", "root"),
            _c("root", "toor"),
            _c("root", "password"),
            _c("root", ""),
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("user", "user"),
            _c("test", "test"),
            _c("guest", "guest"),
            _c("pi", "raspberry"),
            _c("ubuntu", "ubuntu"),
        ],
    ),
    SoftwareEntry(
        name="telnet",
        aliases=["telnet server", "telnetd"],
        category="remote_access",
        default_ports=[23],
        protocols=["telnet"],
        credentials=[
            _c("root", "root"),
            _c("root", ""),
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("admin", "1234"),
            _c("user", "user"),
        ],
    ),
    SoftwareEntry(
        name="vnc",
        aliases=["vnc server", "realvnc", "tightvnc", "ultravnc", "tigervnc"],
        category="remote_access",
        default_ports=[5900, 5901, 5902],
        protocols=["vnc"],
        credentials=[
            _c("", ""),
            _c("", "password"),
            _c("", "vnc"),
            _c("", "1234"),
        ],
    ),
    SoftwareEntry(
        name="rdp",
        aliases=["remote desktop", "mstsc", "ms-wbt-server",
                 "microsoft remote desktop"],
        category="remote_access",
        default_ports=[3389],
        protocols=["rdp"],
        credentials=[
            _c("administrator", ""),
            _c("administrator", "password"),
            _c("administrator", "Password1"),
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),

    # ── File Transfer & Sharing ──────────────────────────────────────────

    SoftwareEntry(
        name="ftp",
        aliases=["vsftpd", "proftpd", "pure-ftpd", "filezilla server",
                 "ftp server"],
        category="file_transfer",
        default_ports=[21],
        protocols=["ftp"],
        credentials=[
            _c("anonymous", ""),
            _c("anonymous", "anonymous@"),
            _c("ftp", "ftp"),
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("root", "root"),
            _c("user", "user"),
        ],
    ),
    SoftwareEntry(
        name="smb",
        aliases=["samba", "cifs", "microsoft-ds", "smb server",
                 "windows file sharing"],
        category="file_transfer",
        default_ports=[445, 139],
        protocols=["smb", "cifs"],
        credentials=[
            _c("administrator", ""),
            _c("administrator", "password"),
            _c("admin", "admin"),
            _c("guest", ""),
            _c("", ""),
        ],
    ),
    SoftwareEntry(
        name="tftp",
        aliases=["tftp server", "tftpd"],
        category="file_transfer",
        default_ports=[69],
        protocols=["tftp"],
        credentials=[
            _c("", "", "typically no auth"),
        ],
    ),
    SoftwareEntry(
        name="nfs",
        aliases=["nfs server", "nfsd"],
        category="file_transfer",
        default_ports=[2049, 111],
        protocols=["nfs", "rpc"],
        credentials=[
            _c("", "", "auth via host/IP allowlisting"),
        ],
    ),

    # ── Mail Servers ─────────────────────────────────────────────────────

    SoftwareEntry(
        name="smtp",
        aliases=["postfix", "exim", "sendmail", "exchange smtp",
                 "smtp server"],
        category="mail",
        default_ports=[25, 465, 587],
        protocols=["smtp", "smtps"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
            _c("postmaster", "postmaster"),
        ],
    ),
    SoftwareEntry(
        name="imap",
        aliases=["dovecot", "courier imap", "imap server"],
        category="mail",
        default_ports=[143, 993],
        protocols=["imap", "imaps"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="pop3",
        aliases=["pop3 server", "pop server"],
        category="mail",
        default_ports=[110, 995],
        protocols=["pop3", "pop3s"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),

    # ── SNMP ─────────────────────────────────────────────────────────────

    SoftwareEntry(
        name="snmp",
        aliases=["snmp agent", "snmpd"],
        category="network_mgmt",
        default_ports=[161, 162],
        protocols=["snmp"],
        credentials=[
            _c("", "public", "read community string"),
            _c("", "private", "write community string"),
            _c("", "community", "community string"),
            _c("", "snmp", "community string"),
            _c("", "default", "community string"),
            _c("", "manager", "community string"),
            _c("", "monitor", "community string"),
        ],
    ),

    # ── IPMI/BMC ─────────────────────────────────────────────────────────

    SoftwareEntry(
        name="ipmi",
        aliases=["bmc", "idrac", "ilo", "imm", "ipmi bmc",
                 "dell idrac", "hp ilo", "supermicro ipmi"],
        category="hardware_mgmt",
        default_ports=[623, 80, 443],
        protocols=["ipmi", "http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("ADMIN", "ADMIN"),
            _c("root", "calvin", "Dell iDRAC"),
            _c("Administrator", "", "HP iLO"),
            _c("USERID", "PASSW0RD", "IBM IMM"),
            _c("admin", "password"),
        ],
    ),

    # ── Printers ─────────────────────────────────────────────────────────

    SoftwareEntry(
        name="printer",
        aliases=["hp printer", "xerox printer", "brother printer",
                 "canon printer", "epson printer", "ricoh printer",
                 "lexmark printer", "cups", "jetdirect"],
        category="printer",
        default_ports=[80, 443, 631, 9100],
        protocols=["http", "https", "ipp", "jetdirect"],
        credentials=[
            _c("admin", ""),
            _c("admin", "admin"),
            _c("admin", "1234"),
            _c("admin", "password"),
            _c("", ""),
        ],
    ),

    # ── IoT & Embedded ───────────────────────────────────────────────────

    SoftwareEntry(
        name="hikvision",
        aliases=["hikvision dvr", "hikvision camera", "hikvision nvr"],
        category="iot",
        default_ports=[80, 443, 8000],
        protocols=["http", "https", "rtsp"],
        credentials=[
            _c("admin", "12345"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="dahua",
        aliases=["dahua camera", "dahua dvr", "dahua nvr"],
        category="iot",
        default_ports=[80, 443, 37777],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("888888", "888888"),
            _c("666666", "666666"),
        ],
    ),
    SoftwareEntry(
        name="axis",
        aliases=["axis camera", "axis communications"],
        category="iot",
        default_ports=[80, 443],
        protocols=["http", "https", "rtsp"],
        credentials=[
            _c("root", "pass"),
            _c("root", "root"),
        ],
    ),
    SoftwareEntry(
        name="raspberry-pi",
        aliases=["raspberry pi", "raspbian", "raspberry pi os"],
        category="iot",
        default_ports=[22],
        protocols=["ssh"],
        credentials=[
            _c("pi", "raspberry"),
            _c("root", "raspberry"),
        ],
    ),

    # ── VPN & Security Appliances ────────────────────────────────────────

    SoftwareEntry(
        name="openvpn",
        aliases=["openvpn as", "openvpn access server"],
        category="vpn",
        default_ports=[943, 1194, 443],
        protocols=["https", "openvpn"],
        credentials=[
            _c("openvpn", "openvpn"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="pfsense",
        aliases=["pf sense", "netgate pfsense"],
        category="firewall",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "pfsense"),
        ],
    ),
    SoftwareEntry(
        name="opnsense",
        aliases=["opn sense"],
        category="firewall",
        default_ports=[80, 443],
        protocols=["http", "https"],
        credentials=[
            _c("root", "opnsense"),
        ],
    ),
    SoftwareEntry(
        name="sophos",
        aliases=["sophos xg", "sophos utm", "sophos firewall"],
        category="firewall",
        default_ports=[4444, 443],
        protocols=["https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),

    # ── Virtualization & Cloud ───────────────────────────────────────────

    SoftwareEntry(
        name="esxi",
        aliases=["vmware esxi", "vsphere", "vcenter", "vmware vsphere"],
        category="virtualization",
        default_ports=[443, 902, 9443],
        protocols=["https"],
        credentials=[
            _c("root", ""),
            _c("root", "vmware"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="proxmox",
        aliases=["proxmox ve", "proxmox virtual environment"],
        category="virtualization",
        default_ports=[8006],
        protocols=["https"],
        credentials=[
            _c("root", ""),
            _c("root", "password"),
        ],
    ),

    # ── LDAP / Directory ─────────────────────────────────────────────────

    SoftwareEntry(
        name="ldap",
        aliases=["openldap", "ldap server", "active directory",
                 "389 directory server"],
        category="directory",
        default_ports=[389, 636],
        protocols=["ldap", "ldaps"],
        credentials=[
            _c("admin", "admin"),
            _c("cn=admin", "admin"),
            _c("administrator", "password"),
        ],
    ),

    # ── API Frameworks (Siphon targets) ──────────────────────────────────

    SoftwareEntry(
        name="swagger",
        aliases=["swagger ui", "openapi", "swagger editor"],
        category="api",
        default_ports=[80, 443, 8080],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("admin", "password"),
        ],
    ),
    SoftwareEntry(
        name="hasura",
        aliases=["hasura graphql", "hasura console"],
        category="api",
        default_ports=[8080],
        protocols=["http", "https"],
        credentials=[
            _c("", "admin", "admin secret header"),
        ],
    ),
    SoftwareEntry(
        name="kong",
        aliases=["kong gateway", "kong api gateway"],
        category="api",
        default_ports=[8000, 8001, 8443, 8444],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),

    # ── Misc Services ────────────────────────────────────────────────────

    SoftwareEntry(
        name="meshcentral",
        aliases=["mesh central", "meshcentral server"],
        category="remote_mgmt",
        default_ports=[443, 4433],
        protocols=["https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="webmin",
        aliases=["webmin server"],
        category="admin_panel",
        default_ports=[10000],
        protocols=["https"],
        credentials=[
            _c("root", "root"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="cockpit",
        aliases=["cockpit server", "cockpit-ws"],
        category="admin_panel",
        default_ports=[9090],
        protocols=["https"],
        credentials=[
            _c("root", "root"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="splunk",
        aliases=["splunk enterprise", "splunk server"],
        category="siem",
        default_ports=[8000, 8089],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "changeme"),
            _c("admin", "admin"),
        ],
    ),
    SoftwareEntry(
        name="wazuh",
        aliases=["wazuh server", "wazuh manager"],
        category="siem",
        default_ports=[443, 55000],
        protocols=["https"],
        credentials=[
            _c("admin", "admin"),
            _c("wazuh", "wazuh"),
        ],
    ),
    SoftwareEntry(
        name="docker-registry",
        aliases=["docker registry", "container registry"],
        category="container",
        default_ports=[5000],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
            _c("", "", "often no auth"),
        ],
    ),
    SoftwareEntry(
        name="hashicorp-vault",
        aliases=["vault", "hashicorp vault server"],
        category="secrets_mgmt",
        default_ports=[8200],
        protocols=["http", "https"],
        credentials=[
            _c("", "", "token-based auth — check for unsealed/dev mode"),
        ],
    ),
    SoftwareEntry(
        name="keycloak",
        aliases=["keycloak server", "red hat sso"],
        category="identity",
        default_ports=[8080, 8443],
        protocols=["http", "https"],
        credentials=[
            _c("admin", "admin"),
        ],
    ),
]


# ── Index ────────────────────────────────────────────────────────────────────

_BY_NAME: Dict[str, SoftwareEntry] = {}
_BY_PORT: Dict[int, List[SoftwareEntry]] = {}
_BY_CATEGORY: Dict[str, List[SoftwareEntry]] = {}

def _build_index():
    _BY_NAME.clear()
    _BY_PORT.clear()
    _BY_CATEGORY.clear()
    for entry in _DATABASE:
        key = entry.name.lower()
        _BY_NAME[key] = entry
        for alias in entry.aliases:
            _BY_NAME[alias.lower()] = entry
        for port in entry.default_ports:
            _BY_PORT.setdefault(port, []).append(entry)
        _BY_CATEGORY.setdefault(entry.category, []).append(entry)

_build_index()


# ── Public API ───────────────────────────────────────────────────────────────

def get_creds(name: str) -> List[Credential]:
    """Look up default credentials by software/service name.

    Matches exact name, aliases, and partial matches (case-insensitive).
    Returns list of Credential(username, password, note).
    """
    entry = _BY_NAME.get(name.lower())
    if entry:
        return list(entry.credentials)

    # Partial match
    nl = name.lower()
    for key, ent in _BY_NAME.items():
        if nl in key or key in nl:
            return list(ent.credentials)
    return []


def get_entry(name: str) -> Optional[SoftwareEntry]:
    """Get the full SoftwareEntry for a name/alias."""
    entry = _BY_NAME.get(name.lower())
    if entry:
        return entry
    nl = name.lower()
    for key, ent in _BY_NAME.items():
        if nl in key or key in nl:
            return ent
    return None


def get_pairs(name: str) -> List[Tuple[str, str]]:
    """Get (username, password) tuples for a software/service name."""
    creds = get_creds(name)
    return [(c.username, c.password) for c in creds]


def get_creds_by_port(port: int) -> Dict[str, List[Credential]]:
    """Get all default credentials for services on a specific port.

    Returns {software_name: [Credential, ...]}.
    """
    result = {}
    for entry in _BY_PORT.get(port, []):
        result[entry.name] = list(entry.credentials)
    return result


def get_creds_by_category(category: str) -> Dict[str, List[Credential]]:
    """Get all default credentials for a category.

    Categories: web_server, cms, ci_cd, monitoring, database, network,
    remote_access, file_transfer, mail, iot, vpn, firewall, api, etc.
    """
    result = {}
    for entry in _BY_CATEGORY.get(category, []):
        result[entry.name] = list(entry.credentials)
    return result


def search(query: str) -> List[SoftwareEntry]:
    """Fuzzy search for software entries by name."""
    ql = query.lower()
    results = []
    seen: Set[str] = set()
    for key, entry in _BY_NAME.items():
        if ql in key and entry.name not in seen:
            seen.add(entry.name)
            results.append(entry)
    return results


def list_categories() -> List[str]:
    """List all available categories."""
    return sorted(_BY_CATEGORY.keys())


def list_software() -> List[str]:
    """List all primary software names."""
    return sorted(set(e.name for e in _DATABASE))


def get_for_service(service_name: str, port: int = 0) -> List[Credential]:
    """Smart lookup combining service name and port for best match.

    Tries exact name match first, then port-based lookup, then partial
    name match. Best used by tools that have both nmap service name and
    port number.
    """
    # Exact name match
    creds = get_creds(service_name)
    if creds:
        return creds

    # Port-based lookup
    if port:
        port_creds = get_creds_by_port(port)
        if port_creds:
            # If service name partially matches a port entry, prefer that
            for sw_name, sw_creds in port_creds.items():
                entry = _BY_NAME.get(sw_name.lower())
                if entry:
                    names = [entry.name.lower()] + [a.lower() for a in entry.aliases]
                    sl = service_name.lower()
                    if any(sl in n or n in sl for n in names):
                        return sw_creds
            # Otherwise return all creds for that port
            all_creds = []
            seen = set()
            for sw_creds in port_creds.values():
                for c in sw_creds:
                    key = (c.username, c.password)
                    if key not in seen:
                        seen.add(key)
                        all_creds.append(c)
            return all_creds

    return []


def export_pairs_file(name: str, output: str):
    """Export user:pass pairs to a file (one per line, colon-separated)."""
    pairs = get_pairs(name)
    with open(output, "w") as f:
        for u, p in pairs:
            f.write(f"{u}:{p}\n")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="pr0t31n_default_creds — default credential database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --lookup tomcat
  %(prog)s --port 3306
  %(prog)s --search apache
  %(prog)s --category database
  %(prog)s --export-pairs tomcat -o creds.txt
  %(prog)s --list-categories
  %(prog)s --list-software
  %(prog)s --dump
""")
    p.add_argument("--lookup", "-l", help="Look up creds by software name")
    p.add_argument("--port", "-p", type=int, help="Look up creds by port")
    p.add_argument("--search", "-s", help="Fuzzy search by name")
    p.add_argument("--category", "-c", help="List creds by category")
    p.add_argument("--service", help="Smart lookup by service name + port",
                   nargs="?", const="")
    p.add_argument("--export-pairs", help="Export user:pass pairs for a software")
    p.add_argument("-o", "--output", help="Output file (for --export-pairs)")
    p.add_argument("--list-categories", action="store_true")
    p.add_argument("--list-software", action="store_true")
    p.add_argument("--dump", action="store_true", help="Dump entire database as JSON")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args()

    if args.list_categories:
        for cat in list_categories():
            count = len(_BY_CATEGORY[cat])
            print(f"  {cat:20s}  ({count} entries)")
        return

    if args.list_software:
        for sw in list_software():
            entry = _BY_NAME[sw]
            print(f"  {sw:25s}  {entry.category:15s}  "
                  f"ports={entry.default_ports}  "
                  f"creds={len(entry.credentials)}")
        return

    if args.dump:
        out = []
        for entry in _DATABASE:
            out.append({
                "name": entry.name,
                "aliases": entry.aliases,
                "category": entry.category,
                "default_ports": entry.default_ports,
                "protocols": entry.protocols,
                "credentials": [asdict(c) for c in entry.credentials],
            })
        print(json.dumps(out, indent=2))
        return

    if args.export_pairs:
        outfile = args.output or f"{args.export_pairs}_creds.txt"
        export_pairs_file(args.export_pairs, outfile)
        print(f"Exported to {outfile}")
        return

    if args.lookup:
        entry = get_entry(args.lookup)
        if not entry:
            print(f"No entry found for '{args.lookup}'")
            sys.exit(1)
        _print_entry(entry)
        return

    if args.port:
        by_port = get_creds_by_port(args.port)
        if not by_port:
            print(f"No entries for port {args.port}")
            sys.exit(1)
        for sw, creds in by_port.items():
            entry = _BY_NAME[sw]
            _print_entry(entry)
            print()
        return

    if args.search:
        results = search(args.search)
        if not results:
            print(f"No matches for '{args.search}'")
            sys.exit(1)
        for entry in results:
            _print_entry(entry)
            print()
        return

    if args.category:
        by_cat = get_creds_by_category(args.category)
        if not by_cat:
            print(f"No entries for category '{args.category}'")
            print(f"Available: {', '.join(list_categories())}")
            sys.exit(1)
        for sw, creds in by_cat.items():
            entry = _BY_NAME[sw]
            _print_entry(entry)
            print()
        return

    if args.service is not None:
        svc = args.service
        port = args.port or 0
        creds = get_for_service(svc, port)
        if not creds:
            print(f"No creds for service='{svc}' port={port}")
            sys.exit(1)
        print(f"Credentials for service='{svc}' port={port}:")
        for c in creds:
            note = f"  ({c.note})" if c.note else ""
            print(f"  {c.username or '(empty)':20s}  {c.password or '(empty)':20s}{note}")
        return

    p.print_help()


def _print_entry(entry: SoftwareEntry):
    print(f"  {entry.name}")
    print(f"    Category:  {entry.category}")
    print(f"    Aliases:   {', '.join(entry.aliases[:5])}")
    print(f"    Ports:     {entry.default_ports}")
    print(f"    Protocols: {entry.protocols}")
    print(f"    Credentials ({len(entry.credentials)}):")
    for c in entry.credentials:
        note = f"  ({c.note})" if c.note else ""
        print(f"      {c.username or '(empty)':20s}  {c.password or '(empty)':20s}{note}")


if __name__ == "__main__":
    main()
