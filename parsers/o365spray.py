"""Parser for o365spray output — account enumeration and password spray results.

o365spray produces different output depending on the mode and flags:

Enum mode (``--enum``):
  --output <dir>   Creates a directory containing:
                     valid_accounts.txt / enum_valid_accounts.txt
                     tested_accounts.txt / enum_tested_accounts.txt
                     (Plus stdout with [VALID]/[INVALID] lines)

  No --output      Prints [VALID]/[INVALID] lines to stdout only.
                   When captured to a file, the parser extracts
                   [VALID] lines via regex.

Spray mode (``--spray``):
  --output <dir>   Creates a directory containing:
                     valid_credentials.txt / spray_valid_credentials.txt
                     tested_credentials.txt
                     (Plus stdout with [SUCCESS]/[FAILED] lines)

The parser handles ALL of the above.  It auto-detects:
  1. Directory with o365spray output files → parse the valid_* file
  2. Text file with [VALID] / [SUCCESS] lines → regex extraction
  3. Text file listing one email per line (valid_accounts.txt) → direct

Content changes based on flags:
  --enum -U <file> --domain <domain>
      Output contains [VALID] <email> for valid accounts
  --spray -U <file> -p <password> --domain <domain>
      Output contains [SUCCESS] <email>:<password> for valid creds
  --spray --paired -C <combo_file>
      Combo file mode: user:pass pairs, output same as spray
  --validate
      Validates O365 tenant, output is just [VALID_DOMAIN] / [INVALID_DOMAIN]
"""

import re
import sys
from pathlib import Path

_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)
_shared = str(Path(__file__).resolve().parent.parent)
if _shared not in sys.path:
    sys.path.insert(0, _shared)

from _base import ToolParser, _make_finding, log

_RE_VALID_ACCOUNT = re.compile(r'\[VALID\]\s+(\S+@\S+)', re.IGNORECASE)
_RE_VALID_CRED = re.compile(
    r'\[SUCCESS\]\s+(\S+@\S+)[:\s]+(\S+)', re.IGNORECASE)
_RE_VALID_DOMAIN = re.compile(
    r'\[VALID[_ ]?DOMAIN\]\s+(\S+)', re.IGNORECASE)

_VALID_ACCOUNT_FILES = {
    "valid_accounts.txt", "enum_valid_accounts.txt",
}
_VALID_CRED_FILES = {
    "valid_credentials.txt", "spray_valid_credentials.txt",
}


class O365SprayParser(ToolParser):
    tool_name = "o365spray"
    supported_formats = ["dir", "text"]

    def detect(self, path: Path) -> bool:
        path = Path(path)
        if path.is_dir():
            names = {f.name.lower() for f in path.iterdir() if f.is_file()}
            if names & (_VALID_ACCOUNT_FILES | _VALID_CRED_FILES):
                return True
            if any("tested_accounts" in n or "tested_credentials" in n
                   for n in names):
                return True
            return False

        if not path.is_file():
            return False
        name = path.name.lower()
        if name in _VALID_ACCOUNT_FILES | _VALID_CRED_FILES:
            return True

        head = self._sniff_head(path)
        if _RE_VALID_ACCOUNT.search(head):
            return True
        if _RE_VALID_CRED.search(head):
            return True
        if _RE_VALID_DOMAIN.search(head):
            return True
        if "[INVALID]" in head and ("o365" in head.lower()
                                     or "@" in head):
            return True
        return False

    def detect_format(self, path: Path) -> str:
        path = Path(path)
        if path.is_dir():
            return "dir"
        return "text"

    def parse(self, path: Path, *,
              target: str = "",
              scope: "str | None" = None,
              phase: str = "",
              tool_flags: "str | None" = None,
              ) -> "list[dict]":
        path = Path(path)
        if path.is_dir():
            return self._parse_dir(path, target=target, scope=scope,
                                   phase=phase)
        return self._parse_text(path, target=target, scope=scope,
                                phase=phase)

    def _parse_dir(self, dir_path: Path, **kwargs) -> "list[dict]":
        findings = []

        valid_accounts_file = None
        valid_creds_file = None

        for f in dir_path.iterdir():
            if not f.is_file():
                continue
            name = f.name.lower()
            if name in _VALID_ACCOUNT_FILES:
                valid_accounts_file = f
            elif name in _VALID_CRED_FILES:
                valid_creds_file = f

        if valid_creds_file:
            findings.extend(self._parse_cred_file(valid_creds_file, **kwargs))
        if valid_accounts_file:
            findings.extend(self._parse_account_file(
                valid_accounts_file, **kwargs))

        if not findings:
            for f in sorted(dir_path.iterdir()):
                if f.is_file() and f.suffix in (".txt", ".log", ""):
                    head = self._sniff_head(f)
                    if _RE_VALID_ACCOUNT.search(head) or \
                       _RE_VALID_CRED.search(head):
                        findings.extend(self._parse_text(f, **kwargs))
                        break

        return findings

    def _parse_text(self, path: Path, **kwargs) -> "list[dict]":
        """Parse a stdout capture or results file with [VALID]/[SUCCESS]."""
        text = self._read_text(path)
        if not text:
            return []

        findings = []

        valid_accounts = []
        for m in _RE_VALID_ACCOUNT.finditer(text):
            valid_accounts.append(m.group(1).strip())

        valid_creds = []
        for m in _RE_VALID_CRED.finditer(text):
            valid_creds.append((m.group(1).strip(), m.group(2).strip()))

        if valid_accounts:
            findings.extend(self._build_enum_findings(
                valid_accounts, source_file=str(path), **kwargs))

        if valid_creds:
            findings.extend(self._build_spray_findings(
                valid_creds, source_file=str(path), **kwargs))

        return findings

    def _parse_account_file(self, path: Path, **kwargs) -> "list[dict]":
        """Parse a valid_accounts.txt — one email per line."""
        text = self._read_text(path)
        if not text:
            return []
        accounts = [line.strip() for line in text.splitlines()
                    if line.strip() and "@" in line]
        if not accounts:
            return []
        return self._build_enum_findings(
            accounts, source_file=str(path), **kwargs)

    def _parse_cred_file(self, path: Path, **kwargs) -> "list[dict]":
        """Parse valid_credentials.txt — email:password per line."""
        text = self._read_text(path)
        if not text:
            return []
        creds = []
        for line in text.splitlines():
            line = line.strip()
            if ":" in line and "@" in line:
                parts = line.split(":", 1)
                creds.append((parts[0].strip(), parts[1].strip()))
        if not creds:
            return []
        return self._build_spray_findings(
            creds, source_file=str(path), **kwargs)

    # ── Finding builders ────────────────────────────────────────

    def _build_enum_findings(self, accounts, *, source_file="",
                              target="", scope=None, phase="",
                              ) -> "list[dict]":
        domain = target
        if not domain and accounts:
            first = accounts[0]
            if "@" in first:
                domain = first.rsplit("@", 1)[1]

        sample = ", ".join(accounts[:10])
        extra = f" (+{len(accounts)-10} more)" if len(accounts) > 10 else ""

        return [_make_finding(
            tool="o365spray",
            title="Enumeration: O365 Account Enumeration",
            ip="",
            port=0,
            hostname=domain,
            risk="MEDIUM",
            scope=scope,
            phase=phase,
            command=f"o365spray --enum --domain {domain}",
            description=(
                f"o365spray confirmed {len(accounts)} valid O365 "
                f"account(s) for {domain}. Valid accounts can be targeted "
                f"with password spray attacks, phishing campaigns, and "
                f"social engineering. Account enumeration is possible "
                f"because the Azure AD authentication endpoint returns "
                f"different responses for valid and invalid accounts."
            ),
            output=f"Valid accounts ({len(accounts)}):\n{sample}{extra}",
            output_file=source_file,
            affected=domain,
            sources="o365spray",
            remediation=(
                "Implement conditional access policies, enforce MFA on all "
                "accounts, and configure Azure AD Smart Lockout. Consider "
                "disabling legacy authentication protocols that bypass MFA. "
                "Monitor Azure AD sign-in logs for enumeration patterns."
            ),
            owasp="A07:2021 - Identification and Authentication Failures",
            cwe=["CWE-200"],
            mitre_attack=[{
                "technique": "T1589.002",
                "tactic": "Reconnaissance",
                "name": "Gather Victim Identity Information: Email Addresses",
            }],
            confidence="Certain",
            source_tools=["o365spray"],
        )]

    def _build_spray_findings(self, creds, *, source_file="",
                               target="", scope=None, phase="",
                               ) -> "list[dict]":
        domain = target
        if not domain and creds:
            email = creds[0][0]
            if "@" in email:
                domain = email.rsplit("@", 1)[1]

        findings = []

        sample_users = ", ".join(c[0] for c in creds[:5])
        extra = f" (+{len(creds)-5} more)" if len(creds) > 5 else ""

        findings.append(_make_finding(
            tool="o365spray",
            title="Authentication: O365 Valid Credentials",
            ip="",
            port=0,
            hostname=domain,
            risk="CRITICAL",
            scope=scope,
            phase=phase,
            command=f"o365spray --spray --domain {domain}",
            description=(
                f"o365spray password spray confirmed {len(creds)} valid "
                f"credential(s) for {domain}. These accounts grant "
                f"authenticated access to Microsoft 365 services "
                f"including Exchange Online, SharePoint, OneDrive, and "
                f"Teams. Compromised credentials may provide access to "
                f"sensitive corporate data and enable lateral movement."
            ),
            output=f"Valid credentials ({len(creds)}):\n{sample_users}{extra}",
            output_file=source_file,
            affected=domain,
            sources="o365spray",
            remediation=(
                "Immediately reset passwords for all compromised accounts. "
                "Enable MFA on all accounts. Review Azure AD sign-in and "
                "audit logs for unauthorized access. Implement Azure AD "
                "Password Protection to block common passwords. Deploy "
                "conditional access policies requiring compliant devices."
            ),
            owasp="A07:2021 - Identification and Authentication Failures",
            cwe=["CWE-521", "CWE-307"],
            mitre_attack=[{
                "technique": "T1110.003",
                "tactic": "Credential Access",
                "name": "Brute Force: Password Spraying",
            }],
            confidence="Certain",
            source_tools=["o365spray"],
        ))

        for email, password in creds:
            findings.append(_make_finding(
                tool="o365spray",
                title=f"Authentication: O365 Credential Confirmed — {email}",
                ip="",
                port=0,
                hostname=domain,
                risk="CRITICAL",
                scope=scope,
                phase=phase,
                command=f"o365spray --spray --domain {domain}",
                description=(
                    f"Valid O365 credential confirmed: {email}. "
                    f"This account grants authenticated access to "
                    f"Microsoft 365 services."
                ),
                output=f"{email}:{password}",
                output_file=source_file,
                affected=email,
                sources="o365spray",
                remediation=(
                    f"Reset password for {email} immediately. Enable MFA. "
                    f"Review sign-in logs for unauthorized access."
                ),
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-521"],
                confidence="Certain",
                source_tools=["o365spray"],
            ))

        return findings
