"""Ánh xạ sự kiện FIM sang kỹ thuật MITRE ATT&CK.

Ba nguồn, theo thứ tự tin cậy:
1. rule Wazuh đã gắn sẵn `rule.mitre.id`;
2. VirusTotal sandbox (behaviour_mitre_trees) — hành vi thực tế của mẫu đã biết;
3. heuristic dựa trên vị trí file / tiến trình ghi file (bảng bên dưới).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import FileEvent, MitreTechnique, VTResult

# Tên kỹ thuật cho các ID hay gặp trong rule Wazuh (rule FIM mặc định gắn T1565.001, T1485, T1070.004).
KNOWN_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1565.001": ("Stored Data Manipulation", "Impact"),
    "T1485": ("Data Destruction", "Impact"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "Persistence"),
    "T1554": ("Compromise Host Software Binary", "Persistence"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "Execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "Defense Evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    "T1197": ("BITS Jobs", "Defense Evasion"),
}


@dataclass(frozen=True)
class PathRule:
    pattern: re.Pattern
    technique: str
    reason: str
    events: frozenset = frozenset({"added", "modified"})


def _re(expr: str) -> re.Pattern:
    return re.compile(expr, re.IGNORECASE)


EXEC_EXT = r"\.(exe|dll|scr|com|pif|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|jar|sh|elf|bin|py|pl)$"
WEB_EXT = r"\.(php\d?|phtml|jsp|jspx|asp|aspx|ashx|cgi)$"
TEMP_DIR = r"(^/tmp/|^/var/tmp/|^/dev/shm/|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\)"
RANSOM_EXT = r"\.(locked|encrypted|enc|crypt|crypted|wncry|wnry|lockbit|ryk|akira|blackcat)$"

PATH_RULES: list[PathRule] = [
    PathRule(_re(r"\\Start Menu\\Programs\\Startup\\"), "T1547.001",
             "File xuất hiện trong thư mục Startup sẽ tự chạy khi người dùng đăng nhập"),
    PathRule(_re(r"^HKEY_.*\\CurrentVersion\\(Run|RunOnce)(Services)?(\\|$)"), "T1547.001",
             "Thay đổi khoá Run/RunOnce trong registry để tự khởi chạy"),
    PathRule(_re(r"^(/etc/cron|/var/spool/cron)"), "T1053.003",
             "Tạo/sửa cron job để duy trì truy cập"),
    PathRule(_re(r"^(/etc/systemd/system|/lib/systemd/system|/usr/lib/systemd/system)/"), "T1543.002",
             "Tạo/sửa systemd service để duy trì truy cập"),
    PathRule(_re(r"/\.ssh/authorized_keys2?$"), "T1098.004",
             "Thêm khoá SSH vào authorized_keys để đăng nhập không cần mật khẩu"),
    PathRule(_re(r"^/etc/(passwd|shadow)$"), "T1136.001",
             "Thay đổi cơ sở dữ liệu tài khoản cục bộ"),
    PathRule(_re(r"^/etc/sudoers(\.d/.*)?$"), "T1548.003",
             "Thay đổi cấu hình sudo"),
    PathRule(_re(r"^/etc/ld\.so\.preload$"), "T1574.006",
             "Chèn thư viện vào mọi tiến trình qua ld.so.preload"),
    PathRule(_re(r"(/\.(bashrc|bash_profile|profile|zshrc)|^/etc/profile(\.d/.*)?|^/etc/bash\.bashrc)$"),
             "T1546.004", "Sửa file cấu hình shell để chạy mã khi đăng nhập"),
    PathRule(_re(r"^(/var/www|/srv/www|/usr/share/nginx/html)/.*" + WEB_EXT), "T1505.003",
             "File script mới trong thư mục web root — dấu hiệu web shell", frozenset({"added"})),
    PathRule(_re(r"\\inetpub\\wwwroot\\.*" + WEB_EXT), "T1505.003",
             "File script mới trong IIS wwwroot — dấu hiệu web shell", frozenset({"added"})),
    PathRule(_re(r"^(/bin|/sbin|/usr/bin|/usr/sbin|/usr/local/bin)/"), "T1554",
             "Binary hệ thống bị thay đổi", frozenset({"modified"})),
    PathRule(_re(r"^C:\\Windows\\System32\\[^\\]+\.(exe|dll)$"), "T1554",
             "Binary hệ thống Windows bị thay đổi", frozenset({"modified"})),
    PathRule(_re(r"(\\Downloads\\|/Downloads/).*" + EXEC_EXT), "T1204.002",
             "File thực thi được tải về thư mục Downloads, chờ người dùng mở", frozenset({"added"})),
    PathRule(_re(TEMP_DIR + r"(.*" + EXEC_EXT + r"|(.*[/\\])?[^/\\.]+$)"), "T1105",
             "File thực thi/không phần mở rộng được thả vào thư mục tạm — nơi hay chứa công cụ tấn công",
             frozenset({"added"})),
    PathRule(_re(r"\.[a-z0-9]{2,4}\.(exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk|sh)$"), "T1036.007",
             "Tên file có hai phần mở rộng để giả dạng tài liệu", frozenset({"added", "modified"})),
    PathRule(_re(RANSOM_EXT), "T1486",
             "Phần mở rộng thường gặp của file bị ransomware mã hoá", frozenset({"added", "modified"})),
]

# Tiến trình ghi file (chỉ có khi bật whodata) -> kỹ thuật thực thi/tải về.
# Chỉ gồm công cụ hay bị lạm dụng để tải/chạy payload (LOLBins); bash/python bị loại vì
# ghi file hợp lệ rất thường xuyên, gây nhiễu.
PROCESS_RULES: list[tuple[re.Pattern, str]] = [
    (_re(r"(^|[\\/])(powershell|pwsh)(\.exe)?$"), "T1059.001"),
    (_re(r"(^|[\\/])(wscript|cscript)(\.exe)?$"), "T1059.005"),
    (_re(r"(^|[\\/])mshta(\.exe)?$"), "T1218.005"),
    (_re(r"(^|[\\/])rundll32(\.exe)?$"), "T1218.011"),
    (_re(r"(^|[\\/])bitsadmin(\.exe)?$"), "T1197"),
    (_re(r"(^|[\\/])(certutil|curl|wget)(\.exe)?$"), "T1105"),
]


def lolbin_technique(process_name: str) -> str | None:
    """Kỹ thuật ATT&CK ứng với tiến trình ghi file, nếu đó là công cụ hay bị lạm dụng (LOLBin)."""
    if not process_name:
        return None
    for pattern, tid in PROCESS_RULES:
        if pattern.search(process_name):
            return tid
    return None


def _technique(tid: str, source: str, reason: str) -> MitreTechnique:
    name, tactic = KNOWN_TECHNIQUES.get(tid, ("", ""))
    return MitreTechnique(id=tid, name=name or tid, tactic=tactic, source=source, reason=reason)  # type: ignore[arg-type]


def map_event(event: FileEvent, vt: VTResult | None = None) -> list[MitreTechnique]:
    found: dict[str, MitreTechnique] = {}

    def add(t: MitreTechnique) -> None:
        found.setdefault(t.id, t)

    for tid in event.rule_mitre_ids:
        add(_technique(tid, "wazuh_rule", f"Rule Wazuh {event.rule_id} gắn sẵn kỹ thuật này"))

    if vt is not None:
        for tech in vt.mitre_techniques:
            add(MitreTechnique(
                id=tech["id"],
                name=tech.get("name") or tech["id"],
                tactic=tech.get("tactic", ""),
                source="virustotal_sandbox",
                reason="Hành vi quan sát được khi chạy mẫu trong sandbox của VirusTotal",
            ))

    for rule in PATH_RULES:
        if event.event in rule.events and rule.pattern.search(event.path):
            add(_technique(rule.technique, "heuristic", rule.reason))

    writer_tid = lolbin_technique(event.process_name)
    if writer_tid:
        add(_technique(writer_tid, "heuristic", f"File được ghi bởi tiến trình {event.process_name}"))

    return list(found.values())
