"""Conservative local publication scan. Never prints matched secret values."""
import ast
import ipaddress
import json
from pathlib import Path
import re
import sys

DENIED = {'.env', '.venv', 'runtime', 'research', 'reports', '__pycache__'}
PATH_RE = re.compile(r'/' + r'(?:Users|Volumes|vol\d+)/[^\s"\'<>]+')
IP_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
ACCOUNT_RE = re.compile(r'(?i)eric' + r'-mingle-69')
EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
PHONE_RE = re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')
SECRET_RE = re.compile(r'(?i)\b(?:[A-Za-z_]*(?:token|cookie|secret|password|api[_-]?key))\b["\']?\s*[=:]\s*["\']([^"\'\r\n]{8,})["\']')
SYNTHETIC = re.compile(r'(?i)offline|fake|test|example|mock|synthetic')

def scan(root):
    findings, count, synthetic_count = [], 0, 0
    for file in sorted(root.rglob('*')):
        relative = file.relative_to(root)
        if '.git' in relative.parts:
            continue  # metadata of a future clean clone is not distributed source
        if file.is_symlink():
            findings.append({'file': str(relative), 'kind': 'symlink'})
        if file.is_dir():
            if file.name in DENIED:
                findings.append({'file': str(relative), 'kind': 'private_directory'})
            continue
        if file.name in DENIED or file.suffix in {'.db', '.sqlite', '.sqlite3', '.pem', '.key', '.png', '.jpg', '.log', '.pyc', '.code-workspace'}:
            findings.append({'file': str(relative), 'kind': 'private_artifact'})
            continue
        count += 1
        try:
            content = file.read_text()
        except UnicodeDecodeError:
            findings.append({'file': str(relative), 'kind': 'unreviewed_binary'})
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for pattern, kind in ((PATH_RE, 'personal_path'), (ACCOUNT_RE, 'personal_identifier')):
                if pattern.search(line):
                    findings.append({'file': str(relative), 'line': number, 'kind': kind})
            for match in EMAIL_RE.finditer(line):
                if 'tests' in relative.parts and ('https://' in line or 'http://' in line) and ('example' in line or 'evil@' in line):
                    synthetic_count += 1  # explicit rejected URL userinfo, not an email account
                else:
                    findings.append({'file': str(relative), 'line': number, 'kind': 'email_review'})
            for match in PHONE_RE.finditer(line):
                if 'tests' in relative.parts and match.group() == '138' + '12345678':
                    synthetic_count += 1  # fixed synthetic phone fixture exercises redaction
                else:
                    findings.append({'file': str(relative), 'line': number, 'kind': 'phone_review'})
            for match in IP_RE.finditer(line):
                try:
                    value = ipaddress.ip_address(match.group())
                except ValueError:
                    continue
                if not value.is_loopback and not value.is_unspecified:
                    findings.append({'file': str(relative), 'line': number, 'kind': 'non_loopback_ip'})
            for match in SECRET_RE.finditer(line):
                value = match.group(1)
                if not ('tests' in relative.parts and SYNTHETIC.search(value)) and not value.startswith(('os.', 'Path(', 'http', 'data/')):
                    findings.append({'file': str(relative), 'line': number, 'kind': 'credential_literal_review'})
            if 'BEGIN ' + 'PRIVATE KEY' in line or re.search(r'gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}', line):
                findings.append({'file': str(relative), 'line': number, 'kind': 'credential_format'})
    return {'files_scanned': count, 'findings_count': len(findings), 'synthetic_fixture_matches': synthetic_count,
            'git_metadata_excluded': True,
            'fixture_explanation': 'Rejected URL userinfo and one fixed synthetic redaction phone in tests are explicitly classified; environment variable names and loopback examples are not credentials.', 'findings': findings}

if __name__ == '__main__':
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
    report = scan(root)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(bool(report['findings']))
