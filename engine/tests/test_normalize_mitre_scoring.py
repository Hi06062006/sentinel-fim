import pytest

from sentinel.mitre import map_event
from sentinel.models import VTResult
from sentinel.normalize import normalize_alert
from sentinel.scoring import score_event, severity_for

from .conftest import EICAR_SHA256, load_sample


def test_normalize_linux_whodata_alert():
    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    assert ev.agent_id == "001"
    assert ev.os_family == "linux"
    assert ev.event == "added"
    assert ev.filename == "eicar.com"
    assert ev.extension == "com"
    assert ev.sha256 == EICAR_SHA256
    assert ev.size == 68
    assert ev.process_name == "/usr/bin/wget"
    assert ev.user_name == "student"


def test_normalize_windows_alert_keeps_rule_mitre():
    ev = normalize_alert(load_sample("02_wannacry_startup_windows.json"))
    assert ev.os_family == "windows"
    assert ev.filename == "tasksche.exe"
    assert ev.rule_mitre_ids == ["T1547.001"]
    assert ev.rule_level == 12


def test_normalize_registry_event():
    alert = {
        "rule": {"id": "752", "level": 5, "groups": ["syscheck", "syscheck_registry"]},
        "agent": {"id": "002", "name": "win"},
        "syscheck": {
            "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "Updater",
            "event": "added",
        },
    }
    ev = normalize_alert(alert)
    assert ev.kind == "registry"
    assert ev.os_family == "windows"
    assert ev.path.endswith("\\Run\\Updater")
    assert [t.id for t in map_event(ev)] == ["T1547.001"]


def test_normalize_wazuh_virustotal_integration_alert():
    alert = {
        "rule": {"id": "87105", "level": 12, "groups": ["virustotal"]},
        "agent": {"id": "001", "name": "lab"},
        "data": {"virustotal": {"positives": "55", "source": {
            "file": "/tmp/x.sh", "sha1": "3395856ce81f2b7382dee72602f798b642f14140"}}},
    }
    ev = normalize_alert(alert)
    assert ev.path == "/tmp/x.sh"
    assert ev.sha1 == "3395856ce81f2b7382dee72602f798b642f14140"
    assert ev.wazuh_virustotal_positives == 55


def test_normalize_rejects_invalid_hash_and_missing_path():
    alert = load_sample("01_eicar_downloads_linux.json")
    alert["syscheck"]["sha256_after"] = "not-a-hash"
    assert normalize_alert(alert).sha256 == ""
    with pytest.raises(ValueError):
        normalize_alert({"rule": {"id": "1"}})


@pytest.mark.parametrize(
    "sample, expected",
    [
        ("01_eicar_downloads_linux.json", {"T1204.002", "T1105"}),
        ("02_wannacry_startup_windows.json", {"T1547.001", "T1059.001"}),
        ("03_webshell_unknown_linux.json", {"T1505.003"}),
        ("04_authorized_keys_modified.json", {"T1098.004"}),
        ("05_benign_pdf_downloads.json", set()),
        ("06_prompt_injection_double_ext.json", {"T1036.007", "T1204.002"}),
    ],
)
def test_mitre_mapping(sample, expected):
    ev = normalize_alert(load_sample(sample))
    assert {t.id for t in map_event(ev)} == expected


def test_mitre_temp_dir_only_flags_executables():
    base = load_sample("01_eicar_downloads_linux.json")
    base["syscheck"].pop("audit")
    for path, flagged in [("/tmp/payload", True), ("/tmp/miner.sh", True), ("/tmp/report.txt", False)]:
        base["syscheck"]["path"] = path
        ids = {t.id for t in map_event(normalize_alert(base))}
        assert ("T1105" in ids) is flagged, path


def found(malicious: int, label: str = "") -> VTResult:
    return VTResult(status="found", malicious=malicious, undetected=70 - malicious, threat_label=label)


def test_score_known_malware_in_downloads_is_high():
    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    score, factors = score_event(ev, found(62, "virus.eicar/test"), map_event(ev))
    codes = {f.code for f in factors}
    assert {"vt_malicious_high", "vt_threat_label", "executable", "lolbin_writer"} <= codes
    assert severity_for(score) in {"high", "critical"}


def test_score_known_ransomware_in_startup_is_critical():
    ev = normalize_alert(load_sample("02_wannacry_startup_windows.json"))
    score, _ = score_event(ev, found(68, "ransomware.wannacry/wanna"), map_event(ev))
    assert severity_for(score) == "critical"


def test_score_unknown_webshell_still_high_from_context():
    """Mẫu chưa từng được báo cáo vẫn bị bắt nhờ ngữ cảnh (vị trí + rule tùy biến)."""
    ev = normalize_alert(load_sample("03_webshell_unknown_linux.json"))
    score, factors = score_event(ev, VTResult(status="not_found"), map_event(ev))
    assert "vt_unknown_executable" in {f.code for f in factors}
    assert severity_for(score) == "high"


def test_score_config_file_without_extension_is_not_executable():
    ev = normalize_alert(load_sample("04_authorized_keys_modified.json"))
    score, factors = score_event(ev, VTResult(status="not_found"), map_event(ev))
    assert {f.code for f in factors} == {"persistence_location", "wazuh_level_12"}
    assert severity_for(score) == "medium"


def test_score_clean_pdf_is_low():
    ev = normalize_alert(load_sample("05_benign_pdf_downloads.json"))
    score, _ = score_event(ev, found(0), map_event(ev))
    assert score == 0
    assert severity_for(score) == "low"


def test_score_allowlisted_is_zero():
    ev = normalize_alert(load_sample("02_wannacry_startup_windows.json"))
    score, factors = score_event(ev, found(68), map_event(ev), allowlisted=True)
    assert score == 0 and factors[0].code == "allowlisted"


def test_score_is_clamped():
    ev = normalize_alert(load_sample("02_wannacry_startup_windows.json"))
    ev.path = ev.path.replace("tasksche.exe", "invoice.pdf.exe")
    score, _ = score_event(ev, found(68, "x"), map_event(ev))
    assert score == 100


def test_sandbox_techniques_do_not_add_context_points():
    """T1486 quan sát trong sandbox VT không có nghĩa file mang phần mở rộng ransomware."""
    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    vt = found(62, "virus.eicar/test")
    vt.mitre_techniques = [{"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
                           {"id": "T1547.001", "name": "Startup", "tactic": "Persistence"}]
    techniques = map_event(ev, vt)
    assert {"T1486", "T1547.001"} <= {t.id for t in techniques}
    score, factors = score_event(ev, vt, techniques)
    codes = {f.code for f in factors}
    assert "ransomware_indicator" not in codes and "persistence_location" not in codes
    assert score == 80


def test_mass_modification_rule_is_high_even_for_office_file():
    alert = load_sample("04_authorized_keys_modified.json")
    alert["rule"] = {"id": "100161", "level": 14, "groups": ["sentinel_fim", "ransomware"],
                     "description": "Mass file modification", "mitre": {"id": ["T1486"]}}
    alert["syscheck"]["path"] = "/srv/share/ke-toan/bao-cao-quy-3.xlsx"
    ev = normalize_alert(alert)
    score, factors = score_event(ev, VTResult(status="not_found"), map_event(ev))
    assert "ransomware_indicator" in {f.code for f in factors}
    assert severity_for(score) == "high"


def test_ransomware_extension_is_high():
    alert = load_sample("05_benign_pdf_downloads.json")
    alert["rule"] = {"id": "100160", "level": 10, "groups": ["sentinel_fim", "ransomware"],
                     "mitre": {"id": ["T1486"]}}
    alert["syscheck"]["path"] = "c:\\users\\lan\\documents\\hop-dong.docx.lockbit"
    alert["syscheck"]["event"] = "added"
    ev = normalize_alert(alert)
    score, _ = score_event(ev, VTResult(status="not_found"), map_event(ev))
    assert severity_for(score) == "high"
