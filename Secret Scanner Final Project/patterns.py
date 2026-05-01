import re

PATTERNS = {
    'Google API Key': re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    'AWS Access Key ID': re.compile(r"AKIA[0-9A-Z]{16}"),
    'Private Key': re.compile(r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----"),
    'Slack Token': re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
'Password Assignment': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']')
}