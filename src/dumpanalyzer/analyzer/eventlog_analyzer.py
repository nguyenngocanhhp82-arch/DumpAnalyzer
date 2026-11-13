"""
Module phân tích chuyên sâu Windows Event Log (eventlog_analyzer.py).

Tính năng:
1. Thu thập theo cấp độ (Level 1: Critical, 2: Error, 3: Warning) và ID thông tin quan trọng (41, 6008, 1001, 1074...).
2. Hỗ trợ nguồn log máy trực tiếp (System, Application) và nhập file hoặc thư mục .evtx ngoại vi.
3. Phân loại sự kiện tự động theo quy tắc cấu hình trong event_categories.yaml.
4. Phân tích dòng thời gian (Timeline), thống kê theo loại và nguồn.
5. Phát hiện đột biến (Spike / Burst Detection): bùng phát lỗi Disk/mạng/driver trong khoảng thời gian ngắn.
6. Phân tích ngữ cảnh trước sập nguồn (Pre-Crash Context): trích xuất các lỗi xảy ra trước mỗi lần sập nguồn bất thường.
7. Che thông tin nhạy cảm (Privacy Redaction): ẩn tên tài khoản, đường dẫn người dùng, địa chỉ IP.
8. Xuất báo cáo chuyên nghiệp sang file Excel (.xlsx).
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from dumpanalyzer.core.config import get_rules_dir, load_settings
from dumpanalyzer.core.ps_runner import parse_ps_json_output, run_powershell_script
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso, utc_to_local_str
from dumpanalyzer.collectors.eventlog import (
    parse_event_xml,
    parse_kernel_power_41,
    parse_bugcheck_1001_message,
    is_kernel_bugcheck_1001_provider,
)

logger = logging.getLogger("dumpanalyzer.analyzer.eventlog_analyzer")

LEVEL_MAP = {
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
    0: "Information",
}

LEVEL_LABEL_VI = {
    1: "Nghiêm trọng (Critical)",
    2: "Lỗi (Error)",
    3: "Cảnh báo (Warning)",
    4: "Thông tin (Info)",
    5: "Chi tiết (Verbose)",
    0: "Thông tin (Info)",
}

# Các kênh nhật ký Windows chuẩn phục vụ chẩn đoán sự cố phần cứng, crash và hệ thống
DEFAULT_DIAGNOSTIC_CHANNELS = [
    "System",
    "Application",
    "HardwareEvents",
    "Microsoft-Windows-Kernel-WHEA/Errors",
    "Microsoft-Windows-Kernel-WHEA/Operational",
    "Microsoft-Windows-WHEA-Logger/Operational",
    "Microsoft-Windows-Kernel-PnP/Configuration",
    "Microsoft-Windows-Diagnostics-Performance/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-Kernel-Power/Operational",
    "Microsoft-Windows-Storage-Storport/Operational",
    "Microsoft-Windows-DiskDiagnostic/Operational",
    "Microsoft-Windows-WindowsUpdateClient/Operational",
]

# Các ID sự kiện quan trọng ở mức Information (Level 4/0) cần thu thập theo đúng kênh Windows
CURATED_INFO_EVENT_IDS = {
    "System": {
        "Microsoft-Windows-Kernel-Power": [41],
        "EventLog": [6005, 6006, 6008],
        "User32": [1074],
        "Microsoft-Windows-Kernel-General": [12],
        "Microsoft-Windows-WindowsUpdateClient": [19, 20],
        "Microsoft-Windows-WER-SystemErrorReporting": [1001],
        "BugCheck": [1001],
    },
    "Application": {
        "MsiInstaller": [11707, 1033],
        "Windows Error Reporting": [1001],
    },
}


@dataclass
class EventLogItem:
    """Đại diện cho một bản ghi sự kiện Windows Event Log."""
    event_id: int
    provider: str
    channel: str = "System"
    level: int = 4
    level_name: str = "Information"
    level_label_vi: str = "Thông tin (Info)"
    time_created_utc: Optional[str] = None
    event_data: Dict[str, Any] = field(default_factory=dict)
    raw_message: str = ""
    category: str = "other"
    category_name: str = "Khác"
    raw_xml: str = ""
    extra_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventLogItem":
        clean_data = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**clean_data)


@dataclass
class SpikeAlert:
    """Cảnh báo bùng phát số lượng lỗi bất thường trong khoảng thời gian ngắn."""
    provider: str
    category: str
    category_name: str
    count: int
    start_time_utc: str
    end_time_utc: str
    duration_minutes: float
    description: str


@dataclass
class PreCrashContext:
    """Ngữ cảnh các sự kiện cảnh báo/lỗi xảy ra ngay trước một lần sập nguồn bất thường."""
    crash_time_utc: str
    crash_event_id: int
    crash_provider: str
    crash_type: str
    window_minutes: int
    preceding_events: List[EventLogItem] = field(default_factory=list)
    dominant_category: str = "none"
    dominant_category_name: str = "Không có"
    summary: str = ""


@dataclass
class EventLogVerdict:
    """Đánh giá & Kết luận chẩn đoán tổng thể tình trạng hệ thống từ Event Log."""
    health_status: str
    health_score: int
    primary_suspect: str
    primary_suspect_name: str
    confidence: str
    confidence_rationale: str
    risk_summary: str
    key_findings: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    suspect_breakdown: List[Tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventLogAnalysisResult:
    """Kết quả phân tích toàn diện Windows Event Log."""
    events: List[EventLogItem] = field(default_factory=list)
    total_events: int = 0
    level_counts: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    top_providers: List[Tuple[str, int]] = field(default_factory=list)
    spikes: List[SpikeAlert] = field(default_factory=list)
    pre_crash_contexts: List[PreCrashContext] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    source_description: str = "Log máy cục bộ"
    verdict: Optional[EventLogVerdict] = None


# ==============================================================================
# HÀM CHE THÔNG TIN NHẠY CẢM (PRIVACY REDACTION)
# ==============================================================================

def redact_sensitive_text(text: str) -> str:
    """
    Ẩn thông tin nhạy cảm trong chuỗi văn bản sự kiện:
    - Đường dẫn thư mục cá nhân người dùng: C:\\Users\\<ten_nguoi_dung>\\...
    - Địa chỉ IPv4 nội bộ và công cộng
    - Tài khoản Domain\\User
    """
    if not text:
        return ""

    # 1. Che đường dẫn Users: C:\Users\Username hoặc /home/username
    text = re.sub(
        r"(?i)(C:\\Users\\)([^\s\\\"\'<>]+)",
        r"\1[ANONYMIZED_USER]",
        text,
    )
    text = re.sub(
        r"(?i)(/home/)([^\s/\"\'<>]+)",
        r"\1[ANONYMIZED_USER]",
        text,
    )

    # 2. Che địa chỉ IP (IPv4)
    text = re.sub(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "[IP_REDACTED]",
        text,
    )

    # 3. Che Domain\\Username (tránh các tên mặc định của hệ thống và tránh nhầm với đường dẫn file)
    system_accounts = {"NT AUTHORITY", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "WORKGROUP"}
    common_path_dirs = {
        "USERS", "WINDOWS", "SYSTEM32", "SYSWOW64", "PROGRAM FILES", "PROGRAMDATA",
        "APPDATA", "LOCAL", "ROAMING", "DOCUMENTS", "DOWNLOADS", "DESKTOP", "TEMP"
    }
    file_ext_pattern = re.compile(r"\.[a-zA-Z0-9]{1,5}$")

    def _replace_domain_user(match: re.Match) -> str:
        domain = match.group(1).strip()
        user = match.group(2).strip()

        # Không che nếu là tài khoản hệ thống chuẩn
        if domain.upper() in system_accounts or user.upper() in system_accounts:
            return match.group(0)

        # Tránh nhầm với đường dẫn thư mục / file (ví dụ: Documents\data.txt)
        if domain.upper() in common_path_dirs or file_ext_pattern.search(user) or file_ext_pattern.search(domain):
            return match.group(0)

        # Tránh nếu trước domain có dấu \ hoặc : (đang là một phần của đường dẫn file dài)
        start_idx = match.start()
        if start_idx > 0 and text[start_idx - 1] in ("\\", "/", ":"):
            return match.group(0)

        return "[DOMAIN]\\[USER_REDACTED]"

    text = re.sub(
        r"\b([A-Za-z0-9_-]{2,})\s*\\\s*([A-Za-z0-9_.-]{2,})\b",
        _replace_domain_user,
        text,
    )

    return text


def redact_event_item(item: EventLogItem) -> EventLogItem:
    """Tạo bản sao sự kiện với thông tin nhạy cảm đã được che chắn."""
    new_data = {}
    for k, v in item.event_data.items():
        if isinstance(v, str):
            new_data[k] = redact_sensitive_text(v)
        else:
            new_data[k] = v

    return EventLogItem(
        event_id=item.event_id,
        provider=item.provider,
        channel=item.channel,
        level=item.level,
        level_name=item.level_name,
        level_label_vi=item.level_label_vi,
        time_created_utc=item.time_created_utc,
        event_data=new_data,
        raw_message=redact_sensitive_text(item.raw_message),
        category=item.category,
        category_name=item.category_name,
        raw_xml=redact_sensitive_text(item.raw_xml) if item.raw_xml else "",
        extra_info=item.extra_info.copy(),
    )


# ==============================================================================
# QUY TẮC PHÂN LOẠI DANH MỤC SỰ KIỆN
# ==============================================================================

def load_event_categories() -> Dict[str, Any]:
    """Tải cấu hình danh mục từ config/rules/event_categories.yaml."""
    cat_file = get_rules_dir() / "event_categories.yaml"
    if not cat_file.exists():
        return {}
    try:
        import yaml
        with open(cat_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data.get("categories", {})
    except Exception as e:
        logger.warning(f"Lỗi khi đọc file event_categories.yaml: {e}")
    return {}


def categorize_event(
    provider: str,
    event_id: int,
    categories_cfg: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """
    Phân loại một sự kiện vào nhóm nghiệp vụ tương ứng.
    Trả về tuple: (category_key, category_display_name).
    """
    cfg = categories_cfg if categories_cfg is not None else load_event_categories()
    prov_clean = (provider or "").strip().lower()

    for cat_id, cat_info in cfg.items():
        cat_name = cat_info.get("name", cat_id)
        rules = cat_info.get("rules", [])
        for r in rules:
            r_prov = str(r.get("provider", "")).strip().lower()
            if not r_prov:
                continue
            # So khớp linh hoạt provider name
            if r_prov in prov_clean or prov_clean in r_prov:
                r_ids = r.get("ids", [])
                if not r_ids or event_id in r_ids:
                    return cat_id, cat_name

    return "other", "Khác (Chưa phân loại)"


# ==============================================================================
# XÂY DỰNG SCRIPT POWERSHELL THU THẬP LOG THEO CẤP ĐỘ VÀ EVTX
# ==============================================================================

def build_harvest_script(
    channels: Optional[List[str]] = None,
    levels: Optional[List[int]] = None,
    evtx_path: Optional[Union[str, Path]] = None,
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    max_events: int = 2000,
) -> str:
    """
    Tạo script PowerShell chuẩn sử dụng Get-WinEvent -FilterHashtable độc lập từng bộ lọc:
    - Chạy từng bộ lọc trong vòng lặp try/catch để một bộ lọc rỗng không làm sập các bộ lọc khác.
    - Không lọc cứng bằng ProviderName không tồn tại trên máy cục bộ (tránh lỗi 'There is not an event provider...').
    - Xuất NDJSON từng sự kiện qua ForEach-Object | ConvertTo-Json -Depth 4 -Compress để không vượt trần 2MB MaxJsonLength của PowerShell 5.1.
    """
    active_levels = levels or [1, 2, 3]
    active_channels = channels if channels is not None else DEFAULT_DIAGNOSTIC_CHANNELS
    from_dt = parse_to_utc(from_date) if from_date else None
    to_dt = parse_to_utc(to_date) if to_date else None

    level_str = ", ".join(str(lvl) for lvl in active_levels)
    time_filter_lines = []
    if from_dt:
        time_filter_lines.append(f"        StartTime = [datetime]'{from_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
    if to_dt:
        time_filter_lines.append(f"        EndTime = [datetime]'{to_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
    time_clause = ("\n" + "\n".join(time_filter_lines)) if time_filter_lines else ""

    if evtx_path:
        # Chế độ đọc file hoặc thư mục .evtx ngoại vi
        p = Path(evtx_path)
        resolved_path = str(p.resolve()).replace("'", "''")

        evtx_time_lines = []
        if from_dt:
            evtx_time_lines.append(f"                StartTime = [datetime]'{from_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
        if to_dt:
            evtx_time_lines.append(f"                EndTime = [datetime]'{to_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
        evtx_time_clause = ("\n" + "\n".join(evtx_time_lines)) if evtx_time_lines else ""

        ps_script = f"""[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$rawTarget = '{resolved_path}'
if (Test-Path -LiteralPath $rawTarget -PathType Container) {{
    $evtxFiles = @(Get-ChildItem -LiteralPath $rawTarget -Filter '*.evtx' -File -Recurse | Select-Object -ExpandProperty FullName)
}} elseif ($rawTarget -match '\\*') {{
    $evtxFiles = @(Get-ChildItem -Path $rawTarget -Filter '*.evtx' -File -Recurse | Select-Object -ExpandProperty FullName)
}} else {{
    $evtxFiles = @($rawTarget)
}}

if ($evtxFiles.Count -eq 0) {{
    Write-Output '[]'
    exit 0
}}

$collected = New-Object System.Collections.Generic.List[object]
$seen = New-Object "System.Collections.Generic.HashSet[string]"
$fatalErrors = New-Object System.Collections.Generic.List[string]

foreach ($filePath in $evtxFiles) {{
    $fileFilters = @(
        @{{
            Path = $filePath
            Level = @({level_str}){evtx_time_clause}
        }},
        @{{
            Path = $filePath
            Id = @(12, 19, 20, 41, 1001, 1033, 1074, 6005, 6006, 6008, 11707){evtx_time_clause}
        }}
    )
    $fileMatchedAny = $false
    foreach ($ff in $fileFilters) {{
        try {{
            $matched = Get-WinEvent -FilterHashtable $ff -MaxEvents {max_events} -ErrorAction Stop
            foreach ($ev in $matched) {{
                $k = "$($filePath)_$($ev.RecordId)"
                if ($seen.Add($k)) {{
                    $evMsg = ''
                    try {{
                        if ($null -ne $ev.Message) {{ $evMsg = [string]$ev.Message }}
                    }} catch {{}}
                    $evXml = ''
                    try {{
                        $evXml = $ev.ToXml()
                    }} catch {{}}
                    $collected.Add([PSCustomObject]@{{
                        Channel = [System.IO.Path]::GetFileName($filePath)
                        Xml = $evXml
                        Message = $evMsg
                    }})
                    $fileMatchedAny = $true
                }}
                if ($collected.Count -ge {max_events}) {{ break }}
            }}
        }} catch {{
            $fid = "$($_.FullyQualifiedErrorId)"
            $msg = "$($_.Exception.Message)"
            if ($fid -match 'NoMatchingEventsFound' -or $msg -match 'No events were found') {{
                continue
            }}
            $fatalErrors.Add("$($filePath): $msg")
        }}
        if ($collected.Count -ge {max_events}) {{ break }}
    }}

    if (-not $fileMatchedAny -and $collected.Count -lt {max_events} -and $fatalErrors.Count -eq 0) {{
        try {{
            $fbFilter = @{{
                Path = $filePath{evtx_time_clause}
            }}
            $fbMatched = Get-WinEvent -FilterHashtable $fbFilter -MaxEvents {max_events} -ErrorAction Stop
            foreach ($ev in $fbMatched) {{
                $k = "$($filePath)_$($ev.RecordId)"
                if ($seen.Add($k)) {{
                    $evMsg = ''
                    try {{
                        if ($null -ne $ev.Message) {{ $evMsg = [string]$ev.Message }}
                    }} catch {{}}
                    $evXml = ''
                    try {{
                        $evXml = $ev.ToXml()
                    }} catch {{}}
                    $collected.Add([PSCustomObject]@{{
                        Channel = [System.IO.Path]::GetFileName($filePath)
                        Xml = $evXml
                        Message = $evMsg
                    }})
                }}
                if ($collected.Count -ge {max_events}) {{ break }}
            }}
        }} catch {{}}
    }}
    if ($collected.Count -ge {max_events}) {{ break }}
}}

if ($collected.Count -eq 0) {{
    if ($fatalErrors.Count -gt 0) {{
        [Console]::Error.WriteLine(($fatalErrors -join ' | '))
        exit 1
    }}
    Write-Output '[]'
    exit 0
}}

$collected | ForEach-Object {{ $_ | ConvertTo-Json -Depth 4 -Compress }}
"""
        return ps_script

    # Chế độ đọc log trực tiếp trên máy (Live System + Application)
    # Tách riêng bộ lọc từng kênh và lọc theo Id ở mức Information (KHÔNG lọc cứng ProviderName dễ gây lỗi trên máy thiếu provider)
    filter_blocks: List[str] = []

    for ch in active_channels:
        safe_ch = ch.replace("'", "''")
        filter_blocks.append(f"""    @{{
        LogName = '{safe_ch}'
        Level = @({level_str}){time_clause}
    }}""")

    # Khối Thông tin trọng yếu trên System (dựa theo Id thuần để không bao giờ vướng lỗi missing provider)
    sys_info_ids = sorted({i for v in CURATED_INFO_EVENT_IDS.get("System", {}).values() for i in v})
    if sys_info_ids:
        sys_ids_str = ", ".join(str(i) for i in sys_info_ids)
        filter_blocks.append(f"""    @{{
        LogName = 'System'
        Id = @({sys_ids_str}){time_clause}
    }}""")

    # Khối Thông tin trọng yếu trên Application (1001 WER, 1033/11707 MsiInstaller)
    app_info_ids = sorted({i for v in CURATED_INFO_EVENT_IDS.get("Application", {}).values() for i in v})
    if app_info_ids:
        app_ids_str = ", ".join(str(i) for i in app_info_ids)
        filter_blocks.append(f"""    @{{
        LogName = 'Application'
        Id = @({app_ids_str}){time_clause}
    }}""")

    all_filters = ",\n".join(filter_blocks)

    ps_script = f"""[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$filters = @(
{all_filters}
)

$collected = New-Object System.Collections.Generic.List[object]
$seen = New-Object "System.Collections.Generic.HashSet[string]"
$fatalErrors = New-Object System.Collections.Generic.List[string]

foreach ($f in $filters) {{
    try {{
        $batch = Get-WinEvent -FilterHashtable $f -MaxEvents {max_events} -ErrorAction Stop
        foreach ($ev in $batch) {{
            $k = "$($ev.LogName)_$($ev.RecordId)"
            if ($seen.Add($k)) {{
                $collected.Add($ev)
            }}
            if ($collected.Count -ge {max_events}) {{ break }}
        }}
    }} catch {{
        $fid = "$($_.FullyQualifiedErrorId)"
        $msg = "$($_.Exception.Message)"
        if ($fid -match 'NoMatchingEventsFound' -or $msg -match 'No events were found' -or $msg -match 'not an event' -or $msg -match 'could not be found' -or $msg -match 'does not exist' -or $fid -match 'LogDoesNotExist') {{
            continue
        }}
        $fatalErrors.Add($msg)
    }}
    if ($collected.Count -ge {max_events}) {{ break }}
}}

if ($collected.Count -eq 0) {{
    if ($fatalErrors.Count -gt 0) {{
        [Console]::Error.WriteLine(($fatalErrors -join ' | '))
        exit 1
    }}
    Write-Output '[]'
    exit 0
}}

$collected | Sort-Object TimeCreated -Descending | Select-Object -First {max_events} | ForEach-Object {{
    $evMsg = ''
    try {{
        if ($null -ne $_.Message) {{ $evMsg = [string]$_.Message }}
    }} catch {{}}
    $evXml = ''
    try {{
        $evXml = $_.ToXml()
    }} catch {{}}
    [PSCustomObject]@{{
        Channel = $_.LogName
        Xml = $evXml
        Message = $evMsg
    }} | ConvertTo-Json -Depth 4 -Compress
}}
"""
    return ps_script


# ==============================================================================
# HÀM THU THẬP VÀ PHÂN TÍCH SỰ KIỆN CHÍNH
# ==============================================================================

def analyze_event_stream(
    raw_event_records: List[Dict[str, Any]],
    categories_cfg: Optional[Dict[str, Any]] = None,
    source_description: str = "Log máy cục bộ",
    window_minutes: int = 15,
    spike_window_minutes: int = 5,
    spike_threshold: int = 5,
) -> EventLogAnalysisResult:
    """
    Chuyển đổi danh sách record thô (chứa Xml và Message) thành EventLogAnalysisResult
    kèm phân loại, phát hiện đột biến và phân tích ngữ cảnh trước sập.
    """
    cat_cfg = categories_cfg if categories_cfg is not None else load_event_categories()
    items: List[EventLogItem] = []
    seen_keys: Set[str] = set()

    for rec in raw_event_records:
        xml_str = rec.get("Xml") or ""
        msg = rec.get("Message") or ""
        channel = rec.get("Channel") or "System"

        if not xml_str and isinstance(rec.get("event_id"), int):
            # Record đã được parse sẵn (dùng trong test hoặc fixture)
            ev_id = rec.get("event_id", 0)
            prov = rec.get("provider", "")
            t_utc = rec.get("time_created_utc")
            lvl = rec.get("level", 4)
            ev_data = rec.get("event_data", {})
            raw_msg = str(rec.get("raw_message") or msg or "")
        else:
            parsed = parse_event_xml(xml_str)
            ev_id = parsed["event_id"]
            prov = parsed["provider"]
            t_utc = parsed["time_created_utc"]
            lvl = parsed["level"]
            ev_data = parsed["event_data"]
            raw_msg = str(msg or parsed["raw_message"] or "")

        # Tránh trùng lặp sự kiện nếu mảng filter của PowerShell trả về 2 lần
        dedup_key = f"{prov}_{ev_id}_{t_utc}_{channel}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        cat_id, cat_name = categorize_event(prov, ev_id, cat_cfg)
        lvl_name = LEVEL_MAP.get(lvl, "Information")
        lvl_label = LEVEL_LABEL_VI.get(lvl, "Thông tin (Info)")

        item = EventLogItem(
            event_id=ev_id,
            provider=prov,
            channel=channel,
            level=lvl,
            level_name=lvl_name,
            level_label_vi=lvl_label,
            time_created_utc=t_utc,
            event_data=ev_data,
            raw_message=raw_msg,
            category=cat_id,
            category_name=cat_name,
            raw_xml=xml_str,
        )

        # Xử lý làm giàu thông tin đặc thù
        if ev_id == 41 and "Kernel-Power" in prov:
            item.extra_info["kp41"] = parse_kernel_power_41(ev_data)
        elif ev_id == 1001 and is_kernel_bugcheck_1001_provider(prov):
            item.extra_info["wer1001"] = parse_bugcheck_1001_message(raw_msg, ev_data)

        items.append(item)

    # Sắp xếp tăng dần theo thời gian UTC
    items.sort(key=lambda x: x.time_created_utc or "")

    # Thống kê cấp độ và danh mục
    level_counts: Dict[str, int] = {"Critical": 0, "Error": 0, "Warning": 0, "Information": 0}
    category_counts: Dict[str, int] = {}
    provider_counts: Dict[str, int] = {}

    for it in items:
        level_counts[it.level_name] = level_counts.get(it.level_name, 0) + 1
        category_counts[it.category_name] = category_counts.get(it.category_name, 0) + 1
        provider_counts[it.provider] = provider_counts.get(it.provider, 0) + 1

    top_providers = sorted(provider_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Phát hiện đột biến lỗi
    spikes = detect_event_spikes(
        items,
        window_minutes=spike_window_minutes,
        threshold=spike_threshold,
    )

    # Phân tích các sự kiện trước lần sập nguồn bất thường
    pre_crashes = analyze_pre_crash_contexts(
        items,
        window_minutes=window_minutes,
    )

    res = EventLogAnalysisResult(
        events=items,
        total_events=len(items),
        level_counts=level_counts,
        category_counts=category_counts,
        top_providers=top_providers,
        spikes=spikes,
        pre_crash_contexts=pre_crashes,
        warnings=[],
        source_description=source_description,
    )
    res.verdict = evaluate_eventlog_verdict(res)
    return res


# ==============================================================================
# PHÁT HIỆN ĐỘT BIẾN (SPIKE / BURST DETECTION)
# ==============================================================================

def detect_event_spikes(
    events: List[EventLogItem],
    window_minutes: int = 5,
    threshold: int = 5,
) -> List[SpikeAlert]:
    """
    Phát hiện các đợt bùng phát lỗi / cảnh báo bất thường trong khoảng thời gian ngắn.
    Chỉ xét các sự kiện cảnh báo hoặc lỗi (Level 1, 2, 3).
    """
    warning_or_error_events = [e for e in events if e.level in (1, 2, 3) and e.time_created_utc]
    if not warning_or_error_events:
        return []

    spikes: List[SpikeAlert] = []
    # Gom nhóm theo provider
    by_provider: Dict[str, List[EventLogItem]] = {}
    for e in warning_or_error_events:
        by_provider.setdefault(e.provider, []).append(e)

    for prov, p_events in by_provider.items():
        if len(p_events) < threshold:
            continue

        p_events_parsed = []
        for e in p_events:
            dt = parse_to_utc(e.time_created_utc)
            if dt:
                p_events_parsed.append((dt, e))
        p_events_parsed.sort(key=lambda x: x[0])

        i = 0
        n = len(p_events_parsed)
        while i < n:
            start_dt, start_ev = p_events_parsed[i]
            window_end = start_dt + timedelta(minutes=window_minutes)

            j = i
            while j < n and p_events_parsed[j][0] <= window_end:
                j += 1

            count = j - i
            if count >= threshold:
                actual_end_dt = p_events_parsed[j - 1][0]
                duration_min = round((actual_end_dt - start_dt).total_seconds() / 60.0, 1)
                desc = (
                    f"Bùng phát {count} sự kiện {start_ev.category_name} ({prov}) "
                    f"trong vòng {duration_min} phút (từ {utc_to_local_str(to_utc_iso(start_dt))} "
                    f"đến {utc_to_local_str(to_utc_iso(actual_end_dt))})."
                )
                spikes.append(SpikeAlert(
                    provider=prov,
                    category=start_ev.category,
                    category_name=start_ev.category_name,
                    count=count,
                    start_time_utc=to_utc_iso(start_dt),
                    end_time_utc=to_utc_iso(actual_end_dt),
                    duration_minutes=duration_min,
                    description=desc,
                ))
                i = j  # Bỏ qua cửa sổ trùng lặp
            else:
                i += 1

    return spikes


# ==============================================================================
# PHÂN TÍCH NGỮ CẢNH TRƯỚC TẮT MÁY BẤT THƯỜNG (PRE-CRASH CONTEXT)
# ==============================================================================

def analyze_pre_crash_contexts(
    events: List[EventLogItem],
    window_minutes: int = 15,
) -> List[PreCrashContext]:
    """
    Với mỗi lần tắt máy bất thường (Event 41 Kernel-Power hoặc Event 6008 Unexpected Shutdown),
    tìm và gom toàn bộ sự kiện cảnh báo/lỗi xảy ra trong cửa sổ N phút trước đó.
    """
    crash_markers: List[EventLogItem] = []
    for e in events:
        if (e.event_id == 41 and "Kernel-Power" in e.provider) or (e.event_id == 6008 and "EventLog" in e.provider):
            if e.time_created_utc:
                crash_markers.append(e)

    contexts: List[PreCrashContext] = []

    for marker in crash_markers:
        crash_dt = parse_to_utc(marker.time_created_utc)
        if not crash_dt:
            continue

        start_window = crash_dt - timedelta(minutes=window_minutes)

        pre_events = []
        cat_counts: Dict[str, int] = {}

        for e in events:
            if e.level in (1, 2, 3) and e.time_created_utc:
                # Không tính chính sự kiện sập
                if e.event_id in (41, 6008) and e.time_created_utc == marker.time_created_utc:
                    continue
                e_dt = parse_to_utc(e.time_created_utc)
                if e_dt and start_window <= e_dt <= crash_dt:
                    pre_events.append(e)
                    cat_counts[e.category_name] = cat_counts.get(e.category_name, 0) + 1

        dominant_cat = "none"
        dominant_cat_name = "Không phát hiện lỗi trước sập"
        if cat_counts:
            sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
            dominant_cat_name = sorted_cats[0][0]
            dominant_cat = dominant_cat_name.lower()

        crash_type_str = f"Sập bất thường (Event {marker.event_id})"
        if marker.event_id == 41 and "kp41" in marker.extra_info:
            kp = marker.extra_info["kp41"]
            code = kp.get("bugcheck_code", "0x0")
            if code != "0x0":
                crash_type_str = f"Màn hình xanh BSOD ({code})"
            else:
                crash_type_str = "Mất nguồn / Treo cứng đột ngột"

        summary = (
            f"Trong {window_minutes} phút trước {crash_type_str} lúc {utc_to_local_str(marker.time_created_utc)}: "
            f"ghi nhận {len(pre_events)} cảnh báo/lỗi, chủ yếu liên quan đến nhóm '{dominant_cat_name}'."
        )

        contexts.append(PreCrashContext(
            crash_time_utc=marker.time_created_utc,
            crash_event_id=marker.event_id,
            crash_provider=marker.provider,
            crash_type=crash_type_str,
            window_minutes=window_minutes,
            preceding_events=pre_events,
            dominant_category=dominant_cat,
            dominant_category_name=dominant_cat_name,
            summary=summary,
        ))

    return contexts


# ==============================================================================
# ĐÁNH GIÁ SỨC KHỎE VÀ KẾT LUẬN TỔNG THỂ TỪ EVENT LOG
# ==============================================================================

SUSPECT_LABEL_VI_MAP: Dict[str, str] = {
    "storage": "Lưu trữ & Hệ thống tệp (Ổ cứng Disk/NVMe/NTFS)",
    "display_gpu": "Card màn hình & Đồ họa (GPU/Display Driver)",
    "hardware": "Phần cứng hệ thống (WHEA/CPU/RAM/Bo mạch)",
    "power_thermal": "Nguồn điện & Nhiệt độ (Power/Thermal)",
    "crash_reboot": "Sập nguồn & Khởi động bất thường (Kernel-Power/BSOD)",
    "app_service": "Dịch vụ & Ứng dụng (Application/Service Crash)",
    "usb_device": "Thiết bị ngoại vi & USB (PnP/Device)",
    "updates_install": "Cập nhật & Cài đặt hệ thống (Windows Update)",
    "other": "Hệ điều hành / Thành phần khác",
    "clean": "Hệ thống bình thường (Không có lỗi ghi nhận)",
}

DEFAULT_RECOMMENDED_ACTIONS: Dict[str, List[str]] = {
    "storage": [
        "Chạy phần mềm CrystalDiskInfo hoặc Hard Disk Sentinel kiểm tra sức khỏe S.M.A.R.T ổ cứng (chú ý Reallocated Sectors, Uncorrectable Errors, Media/Data Integrity).",
        "Mở Command Prompt (Admin) và chạy lệnh: 'chkdsk C: /f /r' để quét và sửa chữa lỗi cấu trúc tập tin NTFS cũng như cô lập sector lỗi.",
        "Kiểm tra cáp kết nối SATA hoặc tháo lắp vệ sinh chân cắm khe cắm M.2 NVMe; sao lưu dữ liệu quan trọng ngay lập tức phòng ổ hỏng đột ngột.",
    ],
    "display_gpu": [
        "Khởi động Windows vào chế độ Safe Mode, dùng công cụ Display Driver Uninstaller (DDU) để gỡ bỏ hoàn toàn driver card màn hình hiện tại.",
        "Tải và cài đặt phiên bản driver card màn hình mới nhất bản WHQL ổn định trực tiếp từ trang chủ của NVIDIA, AMD hoặc Intel.",
        "Dùng phần mềm FurMark hoặc 3DMark chạy test tải GPU trong 15-30 phút, đồng thời theo dõi nhiệt độ GPU Core và GPU Hotspot (không nên vượt quá 85-90°C).",
    ],
    "power_thermal": [
        "Kiểm tra bộ nguồn máy tính (PSU) - sụt áp đường 12V/5V khi CPU/GPU tải nặng là nguyên nhân hàng đầu gây sập nguồn Kernel-Power 41 (BugCheck 0).",
        "Theo dõi nhiệt độ CPU và GPU bằng HWMonitor hoặc AIDA64 khi chạy tải; vệ sinh quạt tản nhiệt và thay keo tản nhiệt nếu nhiệt độ vượt quá 85°C.",
        "Vào Windows Control Panel > Power Options > Choose what the power buttons do > tắt mục 'Turn on fast startup' (Khởi động nhanh).",
    ],
    "hardware": [
        "Tạo USB Boot MemTest86 và khởi động chạy kiểm tra toàn diện bộ nhớ RAM (chạy tối thiểu 4 passes để phát hiện triệt để lỗi bit nhớ hoặc timing không tương thích).",
        "Truy cập BIOS/UEFI của bo mạch chủ, tạm thời tắt tính năng ép xung RAM (XMP / DOCP / EXPO) và ép xung CPU (PBO) để kiểm tra độ ổn định nguyên bản.",
        "Kiểm tra và cập nhật BIOS của bo mạch chủ lên phiên bản mới nhất từ website chính thức của nhà sản xuất.",
    ],
    "crash_reboot": [
        "Kiểm tra nguồn điện máy tính (PSU), dây cấp nguồn và ổ cắm điện; loại trừ khả năng chập điện hoặc sụt áp lưới điện.",
        "Kiểm tra tab 'Sẵn sàng ghi dump' trong phần mềm để đảm bảo hệ thống đã bật đúng CrashDumpEnabled=1 và Paging File để có file minidump khi sập.",
        "Rà soát các thiết bị ngoại vi mới cắm hoặc các phần mềm/driver mới cài đặt gần thời điểm máy bắt đầu sập.",
    ],
    "app_service": [
        "Mở Command Prompt (Admin) chạy lệnh: 'sfc /scannow' và sau đó 'dism /online /cleanup-image /restorehealth' để phục hồi các file hệ thống Windows bị lỗi.",
        "Rà soát các ứng dụng hoặc dịch vụ được báo lỗi trong danh sách chi tiết sự kiện; gỡ bỏ hoặc cài đặt lại phiên bản mới nhất của ứng dụng đó.",
        "Kiểm tra xem phần mềm diệt virus bên thứ ba hoặc tường lửa có can thiệp chặn các tiến trình dịch vụ chuẩn của Windows hay không.",
    ],
    "usb_device": [
        "Rút toàn bộ các thiết bị ngoại vi USB không thiết yếu (USB hub, máy in, webcam ngoài, tay cầm) và theo dõi xem hệ thống còn phát sinh lỗi hay không.",
        "Vào Device Manager kiểm tra các thiết bị có dấu chấm than màu vàng và cập nhật driver chipset / USB controller từ trang chủ bo mạch chủ.",
    ],
    "updates_install": [
        "Mở Windows Update Settings, kiểm tra lịch sử cập nhật xem có bản cập nhật chất lượng (KB) nào vừa cài đặt gần đây trùng với thời điểm phát sinh lỗi hay không.",
        "Nếu lỗi bắt đầu xảy ra sau khi vừa cập nhật Windows, có thể vào Control Panel > Uninstall a program > View installed updates để tạm gỡ bản vá gây xung đột.",
    ],
    "other": [
        "Mở Command Prompt (Admin) chạy 'sfc /scannow' để sửa các tệp hệ điều hành bị hỏng.",
        "Theo dõi thêm nhật ký sự kiện trong vài ngày tiếp theo để xác định quy luật phát sinh sự cố.",
    ],
    "clean": [
        "Hệ thống hiện tại hoạt động bình thường, không cần can thiệp kỹ thuật bổ sung.",
        "Duy trì thói quen vệ sinh máy tính định kỳ và sao lưu dữ liệu thường xuyên.",
    ],
}


def evaluate_eventlog_verdict(result: EventLogAnalysisResult) -> EventLogVerdict:
    """
    Tổng hợp và đánh giá toàn diện tình trạng sức khỏe máy tính từ Windows Event Log:
    - Tính điểm ổn định hệ thống (Health Score 0-100)
    - Xác định mức độ rủi ro (Ổn định, Cần chú ý, Nguy cơ cao, Nghiêm trọng)
    - Nhận diện thủ phạm / nhóm linh kiện nghi vấn hàng đầu (Primary Suspect)
    - Trích xuất gạch đầu dòng các phát hiện trọng yếu (Key Findings)
    - Đưa ra danh sách hành động khắc phục cụ thể theo thứ tự ưu tiên (Recommended Actions)
    """
    crit_count = result.level_counts.get("Critical", 0)
    err_count = result.level_counts.get("Error", 0)
    warn_count = result.level_counts.get("Warning", 0)
    spike_count = len(result.spikes)
    pre_crash_count = len(result.pre_crash_contexts)

    # Nếu không có sự kiện nào hoặc chỉ có info thông thường
    non_info_events = [e for e in result.events if e.level in (1, 2, 3) or e.event_id in (41, 6008)]
    if not non_info_events and spike_count == 0:
        return EventLogVerdict(
            health_status="Ổn định (Rủi ro thấp)",
            health_score=100,
            primary_suspect="clean",
            primary_suspect_name=SUSPECT_LABEL_VI_MAP["clean"],
            confidence="Thấp",
            confidence_rationale="Không ghi nhận sự kiện cảnh báo hoặc lỗi nghiêm trọng nào trong phạm vi quét.",
            risk_summary=(
                f"Không phát hiện sự cố đáng kể nào từ {result.source_description}. "
                "Hệ thống đang vận hành trong ngưỡng an toàn ổn định."
            ),
            key_findings=["Không ghi nhận sự kiện Critical, Error hoặc Warning trong nhật ký."],
            recommended_actions=list(DEFAULT_RECOMMENDED_ACTIONS["clean"]),
            suspect_breakdown=[(SUSPECT_LABEL_VI_MAP["clean"], 100.0)],
        )

    # 1. Tính điểm sức khỏe hệ thống (0 - 100)
    crit_deduct = min(crit_count * 15, 50)
    err_deduct = min(err_count * 2, 30)
    warn_deduct = min(int(warn_count * 0.5), 15)
    spike_deduct = min(spike_count * 10, 25)
    pre_crash_deduct = min(pre_crash_count * 10, 20)

    total_deduct = crit_deduct + err_deduct + warn_deduct + spike_deduct + pre_crash_deduct
    health_score = max(5, min(100, 100 - total_deduct))

    # 2. Xác định trạng thái sức khỏe
    if health_score >= 85:
        health_status = "Ổn định (Rủi ro thấp)"
    elif health_score >= 65:
        health_status = "Cần chú ý (Rủi ro trung bình)"
    elif health_score >= 40:
        health_status = "Nguy cơ cao (Cần kiểm tra)"
    else:
        health_status = "Nghiêm trọng (Bất ổn định nặng)"

    # 3. Tính điểm phân bổ nghi vấn từng nhóm danh mục
    cat_scores: Dict[str, float] = {}

    for e in result.events:
        c = e.category or "other"
        if e.level == 1:
            cat_scores[c] = cat_scores.get(c, 0.0) + 5.0
        elif e.level == 2:
            cat_scores[c] = cat_scores.get(c, 0.0) + 2.0
        elif e.level == 3:
            cat_scores[c] = cat_scores.get(c, 0.0) + 0.5

    for sp in result.spikes:
        c = sp.category or "other"
        cat_scores[c] = cat_scores.get(c, 0.0) + min(sp.count * 1.5, 20.0)

    for pc in result.pre_crash_contexts:
        for pe in pc.preceding_events:
            c = pe.category or "other"
            cat_scores[c] = cat_scores.get(c, 0.0) + 3.0

    if not cat_scores:
        if crit_count > 0 or pre_crash_count > 0:
            cat_scores["crash_reboot"] = 10.0
        else:
            cat_scores["other"] = 1.0

    total_cat_score = sum(cat_scores.values()) or 1.0
    sorted_cats = sorted(cat_scores.items(), key=lambda x: x[1], reverse=True)

    primary_suspect = sorted_cats[0][0]
    primary_suspect_name = SUSPECT_LABEL_VI_MAP.get(primary_suspect, "Khác")

    suspect_breakdown = [
        (SUSPECT_LABEL_VI_MAP.get(cat, cat), round((score / total_cat_score) * 100.0, 1))
        for cat, score in sorted_cats[:5]
    ]

    # 4. Trích xuất các phát hiện trọng yếu (Key Findings)
    key_findings: List[str] = []

    crash_41_cnt = sum(1 for e in result.events if e.event_id == 41 and "Kernel-Power" in e.provider)
    crash_6008_cnt = sum(1 for e in result.events if e.event_id == 6008 and "EventLog" in e.provider)
    total_unexpected_crashes = crash_41_cnt + crash_6008_cnt
    if total_unexpected_crashes > 0:
        key_findings.append(
            f"Ghi nhận {total_unexpected_crashes} lần sập nguồn bất thường hoặc mất nguồn đột ngột "
            f"(Kernel-Power 41: {crash_41_cnt} lần, EventLog 6008: {crash_6008_cnt} lần)."
        )

    if pre_crash_count > 0:
        dominant_summaries = [f"Lần {idx+1}: {pc.summary}" for idx, pc in enumerate(result.pre_crash_contexts[:2])]
        key_findings.append(
            f"Phát hiện cảnh báo/lỗi dồn dập ngay trước các lần tắt máy bất thường ({'; '.join(dominant_summaries)})."
        )

    if spike_count > 0:
        sp_desc = [f"nhóm '{s.category_name}' ({s.count} lỗi/{s.duration_minutes} phút)" for s in result.spikes[:2]]
        key_findings.append(f"Bùng phát {spike_count} đợt lỗi đột biến (Spikes): {', '.join(sp_desc)}.")

    storage_cnt = sum(1 for e in result.events if e.category == "storage" and e.level in (1, 2, 3))
    if storage_cnt > 0:
        key_findings.append(f"Ghi nhận {storage_cnt} cảnh báo/lỗi đọc ghi hoặc hệ thống tệp ổ cứng (Disk, stornvme, Ntfs).")

    hw_cnt = sum(1 for e in result.events if e.category == "hardware" and e.level in (1, 2, 3))
    if hw_cnt > 0:
        key_findings.append(f"Phát hiện {hw_cnt} sự kiện báo lỗi phần cứng từ bộ xử lý WHEA (WHEA-Logger).")

    gpu_cnt = sum(1 for e in result.events if e.category == "display_gpu" and e.level in (1, 2, 3))
    if gpu_cnt > 0:
        key_findings.append(f"Ghi nhận {gpu_cnt} sự cố trình điều khiển đồ họa bị treo hoặc reset (Display, nvlddmkm).")

    power_cnt = sum(1 for e in result.events if e.category == "power_thermal" and e.level in (1, 2, 3))
    if power_cnt > 0:
        key_findings.append(f"Ghi nhận {power_cnt} cảnh báo nguồn điện hoặc quá nhiệt CPU (Kernel-Processor-Power, ACPI).")

    app_cnt = sum(1 for e in result.events if e.category == "app_service" and e.level in (1, 2, 3))
    if app_cnt > 0:
        key_findings.append(f"Ghi nhận {app_cnt} sự cố ứng dụng hoặc dịch vụ hệ thống bị dừng đột ngột.")

    if not key_findings:
        key_findings.append("Không có mẫu hình sự cố nghiêm trọng tập trung; hệ thống chỉ ghi nhận một số cảnh báo rải rác.")

    # 5. Độ tin cậy (Confidence)
    if crit_count >= 1 or spike_count >= 1 or err_count >= 5:
        confidence = "Cao"
        confidence_rationale = (
            f"Độ tin cậy chẩn đoán cao nhờ phát hiện {crit_count} sự kiện nghiêm trọng (Critical), "
            f"{err_count} lỗi (Error) và {spike_count} đợt bùng phát lỗi dồn dập."
        )
    elif err_count >= 1 or warn_count >= 3:
        confidence = "Trung bình"
        confidence_rationale = f"Độ tin cậy trung bình dựa trên {err_count} lỗi và {warn_count} cảnh báo rải rác."
    else:
        confidence = "Thấp"
        confidence_rationale = "Số lượng sự cố ghi nhận ít, chưa đủ mẫu hình lỗi dày đặc để khẳng định chắc chắn."

    # 6. Tóm tắt rủi ro (Risk Summary)
    top_pct = suspect_breakdown[0][1] if suspect_breakdown else 100.0
    risk_summary = (
        f"Hệ thống đạt điểm ổn định {health_score}/100 ({health_status}). "
        f"Tổng hợp từ {result.source_description} ghi nhận {result.total_events} sự kiện "
        f"({crit_count} Critical, {err_count} Error, {warn_count} Warning). "
        f"Nguy cơ cao nhất tập trung tại nhóm: {primary_suspect_name} (chiếm {top_pct}% trọng số lỗi)."
    )

    # 7. Khuyến nghị xử lý (Recommended Actions)
    recs = list(DEFAULT_RECOMMENDED_ACTIONS.get(primary_suspect, DEFAULT_RECOMMENDED_ACTIONS["other"]))
    if total_unexpected_crashes > 0 and primary_suspect not in ("crash_reboot", "power_thermal"):
        recs.append("Kiểm tra bộ nguồn (PSU) và tab 'Sẵn sàng ghi dump' để đảm bảo máy tính không bị mất nguồn đột ngột.")

    return EventLogVerdict(
        health_status=health_status,
        health_score=health_score,
        primary_suspect=primary_suspect,
        primary_suspect_name=primary_suspect_name,
        confidence=confidence,
        confidence_rationale=confidence_rationale,
        risk_summary=risk_summary,
        key_findings=key_findings,
        recommended_actions=recs,
        suspect_breakdown=suspect_breakdown,
    )


# ==============================================================================
# HÀM THỰC THI THU THẬP LOG (LIVE VÀ TỪ EVTX)
# ==============================================================================

def _execute_harvest_ps(
    ps_script: str,
    source_description: str,
    empty_description: str,
    error_prefix: str,
    debug_ps: bool = False,
) -> EventLogAnalysisResult:
    """Helper dùng chung thực thi script PowerShell thu thập log (Live & .evtx) an toàn."""
    settings = load_settings()
    timeout = int(settings.get("eventlog_timeout_seconds", 120))

    try:
        proc = run_powershell_script(ps_script, timeout=timeout)

        if debug_ps:
            print(f"\n=== DEBUG POWERSHELL ({source_description}) ===")
            print(f"ReturnCode: {proc.returncode}")
            print(f"Stderr: {(proc.stderr or '').strip()}")
            print(f"Output (500 chars):\n{(proc.stdout or '')[:500]}")
            print("=======================================\n")

        stderr_msg = (proc.stderr or "").strip()
        data_list = parse_ps_json_output(proc.stdout or "")

        if proc.returncode != 0:
            err_detail = stderr_msg or f"Mã lỗi {proc.returncode}"
            warn = f"{error_prefix}: {err_detail}"
            logger.warning(warn)
            if data_list:
                res = analyze_event_stream(data_list, source_description=source_description)
                res.warnings.append(warn)
                return res
            return EventLogAnalysisResult(events=[], warnings=[warn], source_description="Lỗi đọc log")

        if not data_list:
            if stderr_msg:
                warn = f"{error_prefix}: {stderr_msg}"
                logger.warning(warn)
                return EventLogAnalysisResult(events=[], warnings=[warn], source_description=empty_description)
            return EventLogAnalysisResult(events=[], source_description=empty_description)

        res = analyze_event_stream(data_list, source_description=source_description)
        if stderr_msg:
            res.warnings.append(stderr_msg)
        return res

    except subprocess.TimeoutExpired:
        warn = f"Quá thời gian chờ ({timeout}s) khi đọc Windows Event Log."
        logger.warning(warn)
        return EventLogAnalysisResult(events=[], warnings=[warn], source_description="Quá thời gian chờ")
    except Exception as e:
        warn = f"{error_prefix}: {e}"
        logger.error(warn)
        return EventLogAnalysisResult(events=[], warnings=[warn], source_description="Lỗi ngoại lệ")


def harvest_live_eventlog(
    channels: Optional[List[str]] = None,
    levels: Optional[List[int]] = None,
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    max_events: int = 2000,
    mock_records: Optional[List[Dict[str, Any]]] = None,
    debug_ps: bool = False,
) -> EventLogAnalysisResult:
    """
    Thu thập log máy tính trực tiếp từ System và Application log.
    Chạy PowerShell trên Windows hoặc dùng mock_records trên môi trường khác.
    """
    if mock_records is not None:
        return analyze_event_stream(
            mock_records,
            source_description="Dữ liệu kiểm thử (Mock Live)",
        )

    ps_script = build_harvest_script(
        channels=channels,
        levels=levels,
        from_date=from_date,
        to_date=to_date,
        max_events=max_events,
    )

    if sys.platform != "win32":
        if debug_ps:
            print("\n=== DEBUG POWERSHELL HARVEST SCRIPT ===")
            print(ps_script)
            print("=======================================\n")
        logger.info("Môi trường non-Windows: Bỏ qua gọi PowerShell trực tiếp.")
        return EventLogAnalysisResult(
            events=[],
            source_description="Môi trường non-Windows (Không thể truy vấn trực tiếp)",
            warnings=["Hệ điều hành hiện tại không phải Windows, chỉ có thể nạp file .evtx hoặc dữ liệu giả lập."],
        )

    return _execute_harvest_ps(
        ps_script=ps_script,
        source_description="Log hệ thống máy cục bộ",
        empty_description="Không có sự kiện khớp trong log máy",
        error_prefix="Lỗi thực thi PowerShell",
        debug_ps=debug_ps,
    )


def harvest_evtx_eventlog(
    evtx_path: Union[str, Path],
    levels: Optional[List[int]] = None,
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    max_events: int = 2000,
    mock_records: Optional[List[Dict[str, Any]]] = None,
    debug_ps: bool = False,
) -> EventLogAnalysisResult:
    """
    Thu thập và phân tích sự kiện từ 1 file .evtx hoặc thư mục chứa các file .evtx.
    Xử lý hoàn toàn cục bộ, bảo mật quyền riêng tư 100%.
    """
    p = Path(evtx_path)
    if not p.exists() and mock_records is None:
        return EventLogAnalysisResult(
            events=[],
            warnings=[f"Đường dẫn file hoặc thư mục .evtx không tồn tại: {evtx_path}"],
            source_description=f"Không tìm thấy {p.name}",
        )

    if mock_records is not None:
        return analyze_event_stream(
            mock_records,
            source_description=f"Tệp .evtx (Mock): {p.name}",
        )

    ps_script = build_harvest_script(
        evtx_path=p,
        levels=levels,
        from_date=from_date,
        to_date=to_date,
        max_events=max_events,
    )

    if sys.platform != "win32":
        if debug_ps:
            print("\n=== DEBUG POWERSHELL EVTX SCRIPT ===")
            print(ps_script)
            print("====================================\n")
        logger.info("Môi trường non-Windows: Không thể gọi Get-WinEvent trên file .evtx thật.")
        return EventLogAnalysisResult(
            events=[],
            source_description=f"File .evtx: {p.name}",
            warnings=["Trên Linux cần chạy trên Windows để dùng Get-WinEvent đọc nhị phân .evtx (hoặc truyền mock_records để test)."],
        )

    return _execute_harvest_ps(
        ps_script=ps_script,
        source_description=f"Tệp .evtx: {p.name}",
        empty_description=f"File .evtx không chứa sự kiện phù hợp ({p.name})",
        error_prefix="Lỗi đọc file .evtx",
        debug_ps=debug_ps,
    )


# ==============================================================================
# XUẤT BÁO CÁO EXCEL ĐA BẢNG TÍNH CHO EVENT LOG (.XLSX)
# ==============================================================================

def export_eventlog_to_excel(
    result: EventLogAnalysisResult,
    output_path: Union[str, Path],
    redact: bool = False,
) -> Path:
    """
    Xuất toàn bộ kết quả phân tích sự kiện sang định dạng Microsoft Excel (.xlsx) đa sheet:
    - Sheet 1: Tổng quan KPI, phân bố danh mục, đột biến lỗi (Spikes), ngữ cảnh trước sập (Pre-Crash).
    - Sheet 2: Danh sách chi tiết toàn bộ sự kiện đã thu thập.
    Hỗ trợ cờ redact để che thông tin cá nhân/IP khi chia sẻ báo cáo ra bên ngoài.
    """
    import openpyxl
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()
    # Sheet 1: Tổng quan
    ws_summary = wb.active
    ws_summary.title = "Tổng quan & Thống kê"

    # Font và màu sắc giao diện Dark/Slate tương thích Excel
    header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    section_fill = PatternFill(start_color="334155", end_color="334155", fill_type="solid")
    section_font = Font(name="Segoe UI", size=12, bold=True, color="FFFFFF")
    bold_font = Font(name="Segoe UI", size=10, bold=True)
    regular_font = Font(name="Segoe UI", size=10)
    thin_border = Border(
        left=Side(style="thin", color="CBD5E1"),
        right=Side(style="thin", color="CBD5E1"),
        top=Side(style="thin", color="CBD5E1"),
        bottom=Side(style="thin", color="CBD5E1"),
    )

    # 1. Tiêu đề chính
    ws_summary["A1"] = "BÁO CÁO PHÂN TÍCH WINDOWS EVENT LOG — DumpAnalyzer"
    ws_summary["A1"].font = Font(name="Segoe UI", size=16, bold=True, color="0F172A")
    ws_summary["A2"] = f"Nguồn dữ liệu: {result.source_description} | Thời điểm xuất: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    ws_summary["A2"].font = Font(name="Segoe UI", size=10, italic=True, color="64748B")
    if redact:
        ws_summary["A3"] = "Lưu ý: Báo cáo đã bật chế độ che thông tin nhạy cảm (Tên người dùng, Đường dẫn, Địa chỉ IP)."
        ws_summary["A3"].font = Font(name="Segoe UI", size=10, bold=True, color="DC2626")

    row_idx = 5

    # 1. Khung Đánh giá tổng thể tình trạng hệ thống (Verdict)
    v = result.verdict
    if v:
        ws_summary.cell(row=row_idx, column=1, value="1. ĐÁNH GIÁ TỔNG THỂ TÌNH TRẠNG HỆ THỐNG (SYSTEM VERDICT)").font = section_font
        for col in range(1, 6):
            ws_summary.cell(row=row_idx, column=col).fill = section_fill
        row_idx += 1

        cell_vh1 = ws_summary.cell(row=row_idx, column=1, value="Chỉ số đánh giá")
        cell_vh1.fill = header_fill
        cell_vh1.font = header_font
        cell_vh1.border = thin_border
        cell_vh2 = ws_summary.cell(row=row_idx, column=2, value="Kết quả / Nội dung phân tích")
        cell_vh2.fill = header_fill
        cell_vh2.font = header_font
        cell_vh2.border = thin_border
        for c in range(3, 6):
            ws_summary.cell(row=row_idx, column=c).border = thin_border
        row_idx += 1

        verdict_rows = [
            ("Tình trạng sức khỏe", v.health_status),
            ("Điểm số ổn định", f"{v.health_score} / 100"),
            ("Thủ phạm / Nhóm nghi vấn hàng đầu", v.primary_suspect_name),
            ("Mức độ tin cậy", f"{v.confidence} — {v.confidence_rationale}"),
            ("Tóm tắt rủi ro hệ thống", v.risk_summary),
            ("Các phát hiện trọng yếu", "\n".join(f"• {k}" for k in v.key_findings)),
            ("Khuyến nghị kỹ thuật ưu tiên", "\n".join(f"{idx}. {act}" for idx, act in enumerate(v.recommended_actions, 1))),
        ]

        for lbl, val_txt in verdict_rows:
            ws_summary.cell(row=row_idx, column=1, value=lbl).font = bold_font
            cell_v = ws_summary.cell(row=row_idx, column=2, value=val_txt)
            cell_v.font = regular_font
            cell_v.alignment = Alignment(wrap_text=True, vertical="top")
            for c in range(1, 6):
                ws_summary.cell(row=row_idx, column=c).border = thin_border
            row_idx += 1

        row_idx += 2

    sec_kpi_title = "2. THỐNG KÊ TỔNG QUAN THEO CẤP ĐỘ" if v else "1. THỐNG KÊ TỔNG QUAN THEO CẤP ĐỘ"
    ws_summary.cell(row=row_idx, column=1, value=sec_kpi_title).font = section_font
    for col in range(1, 5):
        ws_summary.cell(row=row_idx, column=col).fill = section_fill
    row_idx += 1

    headers_kpi = ["Chỉ số", "Số lượng", "Tỷ lệ %", "Đánh giá sơ bộ"]
    for col_idx, h in enumerate(headers_kpi, start=1):
        cell = ws_summary.cell(row=row_idx, column=col_idx, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = thin_border
    row_idx += 1

    tot = max(result.total_events, 1)
    kpis = [
        ("Tổng số sự kiện thu thập", result.total_events, "100.0%", "Toàn bộ sự kiện trong phạm vi quét"),
        ("Nghiêm trọng (Critical)", result.level_counts.get("Critical", 0), f"{(result.level_counts.get('Critical', 0)/tot)*100:.1f}%", "Cần xử lý khẩn cấp"),
        ("Lỗi (Error)", result.level_counts.get("Error", 0), f"{(result.level_counts.get('Error', 0)/tot)*100:.1f}%", "Lỗi dịch vụ/thiết bị"),
        ("Cảnh báo (Warning)", result.level_counts.get("Warning", 0), f"{(result.level_counts.get('Warning', 0)/tot)*100:.1f}%", "Nguy cơ tiềm ẩn"),
        ("Thông tin (Info / Curated)", result.level_counts.get("Information", 0), f"{(result.level_counts.get('Information', 0)/tot)*100:.1f}%", "Mốc vận hành/khởi động"),
    ]
    for label, val, pct, note in kpis:
        ws_summary.cell(row=row_idx, column=1, value=label).font = bold_font
        ws_summary.cell(row=row_idx, column=2, value=val).alignment = Alignment(horizontal="right")
        ws_summary.cell(row=row_idx, column=3, value=pct).alignment = Alignment(horizontal="right")
        ws_summary.cell(row=row_idx, column=4, value=note).font = regular_font
        for c in range(1, 5):
            ws_summary.cell(row=row_idx, column=c).border = thin_border
        row_idx += 1

    row_idx += 2

    # 3. Phân bố theo Danh mục sự kiện
    sec_cat_title = "3. PHÂN BỐ SỰ KIỆN THEO DANH MỤC NGHIỆP VỤ" if v else "2. PHÂN BỐ SỰ KIỆN THEO DANH MỤC NGHIỆP VỤ"
    ws_summary.cell(row=row_idx, column=1, value=sec_cat_title).font = section_font
    for col in range(1, 4):
        ws_summary.cell(row=row_idx, column=col).fill = section_fill
    row_idx += 1

    headers_cat = ["Danh mục", "Số lượng", "Tỷ lệ %"]
    for col_idx, h in enumerate(headers_cat, start=1):
        cell = ws_summary.cell(row=row_idx, column=col_idx, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = thin_border
    row_idx += 1

    for cat_name, c_cnt in sorted(result.category_counts.items(), key=lambda x: x[1], reverse=True):
        ws_summary.cell(row=row_idx, column=1, value=cat_name).font = regular_font
        ws_summary.cell(row=row_idx, column=2, value=c_cnt).alignment = Alignment(horizontal="right")
        ws_summary.cell(row=row_idx, column=3, value=f"{(c_cnt/tot)*100:.1f}%").alignment = Alignment(horizontal="right")
        for c in range(1, 4):
            ws_summary.cell(row=row_idx, column=c).border = thin_border
        row_idx += 1

    row_idx += 2

    # 4. Bảng Đột biến lỗi (Spikes)
    sec_spike_title = "4. CÁC ĐỢT BÙNG PHÁT LỖI ĐỘT BIẾN (SPIKE ALERTS)" if v else "3. CÁC ĐỢT BÙNG PHÁT LỖI ĐỘT BIẾN (SPIKE ALERTS)"
    ws_summary.cell(row=row_idx, column=1, value=sec_spike_title).font = section_font
    for col in range(1, 6):
        ws_summary.cell(row=row_idx, column=col).fill = section_fill
    row_idx += 1

    headers_spike = ["Nguồn (Provider)", "Danh mục", "Số lượng", "Thời lượng (phút)", "Mô tả chi tiết"]
    for col_idx, h in enumerate(headers_spike, start=1):
        cell = ws_summary.cell(row=row_idx, column=col_idx, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = thin_border
    row_idx += 1

    if not result.spikes:
        ws_summary.cell(row=row_idx, column=1, value="Không phát hiện đợt bùng phát lỗi bất thường nào.").font = regular_font
        for c in range(1, 6):
            ws_summary.cell(row=row_idx, column=c).border = thin_border
        row_idx += 1
    else:
        for sp in result.spikes:
            ws_summary.cell(row=row_idx, column=1, value=sp.provider).font = bold_font
            ws_summary.cell(row=row_idx, column=2, value=sp.category_name).font = regular_font
            ws_summary.cell(row=row_idx, column=3, value=sp.count).alignment = Alignment(horizontal="right")
            ws_summary.cell(row=row_idx, column=4, value=sp.duration_minutes).alignment = Alignment(horizontal="right")
            ws_summary.cell(row=row_idx, column=5, value=sp.description).font = regular_font
            for c in range(1, 6):
                ws_summary.cell(row=row_idx, column=c).border = thin_border
            row_idx += 1

    row_idx += 2

    # 5. Bảng Ngữ cảnh trước các lần sập nguồn (Pre-Crash Contexts)
    sec_pre_title = "5. NGỮ CẢNH TRƯỚC CÁC LẦN TẮT MÁY BẤT THƯỜNG / SẬP NGUỒN" if v else "4. NGỮ CẢNH TRƯỚC CÁC LẦN TẮT MÁY BẤT THƯỜNG / SẬP NGUỒN"
    ws_summary.cell(row=row_idx, column=1, value=sec_pre_title).font = section_font
    for col in range(1, 5):
        ws_summary.cell(row=row_idx, column=col).fill = section_fill
    row_idx += 1

    headers_pre = ["Thời điểm sập (Giờ máy)", "Loại sự cố", "Số lỗi trước sập", "Tóm tắt phân tích"]
    for col_idx, h in enumerate(headers_pre, start=1):
        cell = ws_summary.cell(row=row_idx, column=col_idx, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = thin_border
    row_idx += 1

    if not result.pre_crash_contexts:
        ws_summary.cell(row=row_idx, column=1, value="Không có lần tắt máy bất thường (Event 41/6008) nào trong log.").font = regular_font
        for c in range(1, 5):
            ws_summary.cell(row=row_idx, column=c).border = thin_border
    else:
        for pc in result.pre_crash_contexts:
            ws_summary.cell(row=row_idx, column=1, value=utc_to_local_str(pc.crash_time_utc)).font = bold_font
            ws_summary.cell(row=row_idx, column=2, value=pc.crash_type).font = regular_font
            ws_summary.cell(row=row_idx, column=3, value=len(pc.preceding_events)).alignment = Alignment(horizontal="right")
            ws_summary.cell(row=row_idx, column=4, value=pc.summary).font = regular_font
            for c in range(1, 5):
                ws_summary.cell(row=row_idx, column=c).border = thin_border
            row_idx += 1

    # Tự động căn chỉnh độ rộng cột Sheet 1
    for col in ws_summary.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        col_letter = get_column_letter(col[0].column)
        ws_summary.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 65)

    # Sheet 2: Danh sách chi tiết sự kiện
    ws_details = wb.create_sheet(title="Danh sách Sự kiện")
    detail_headers = [
        "STT", "Thời gian (Giờ máy)", "Thời gian UTC", "Mức độ",
        "Danh mục", "Nguồn (Provider)", "Event ID", "Kênh (Channel)",
        "Nội dung sự kiện (Message)", "EventData (Key-Value)"
    ]
    for col_idx, h in enumerate(detail_headers, start=1):
        cell = ws_details.cell(row=1, column=col_idx, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = thin_border

    events_to_write = [redact_event_item(e) for e in result.events] if redact else result.events
    for r_idx, ev in enumerate(events_to_write, start=2):
        ed_str = json.dumps(ev.event_data, ensure_ascii=False) if ev.event_data else ""
        ws_details.cell(row=r_idx, column=1, value=r_idx - 1).alignment = Alignment(horizontal="center")
        ws_details.cell(row=r_idx, column=2, value=utc_to_local_str(ev.time_created_utc))
        ws_details.cell(row=r_idx, column=3, value=ev.time_created_utc or "")
        ws_details.cell(row=r_idx, column=4, value=ev.level_label_vi)
        ws_details.cell(row=r_idx, column=5, value=ev.category_name)
        ws_details.cell(row=r_idx, column=6, value=ev.provider)
        ws_details.cell(row=r_idx, column=7, value=ev.event_id).alignment = Alignment(horizontal="center")
        ws_details.cell(row=r_idx, column=8, value=ev.channel)
        ws_details.cell(row=r_idx, column=9, value=ev.raw_message[:1000] if ev.raw_message else "")
        ws_details.cell(row=r_idx, column=10, value=ed_str[:1000] if ed_str else "")

        for c in range(1, 11):
            ws_details.cell(row=r_idx, column=c).border = thin_border
            ws_details.cell(row=r_idx, column=c).font = regular_font

    # Căn chỉnh độ rộng cột Sheet 2
    col_widths = {1: 8, 2: 20, 3: 22, 4: 20, 5: 22, 6: 25, 7: 12, 8: 15, 9: 50, 10: 40}
    for col_num, w in col_widths.items():
        col_letter = get_column_letter(col_num)
        ws_details.column_dimensions[col_letter].width = w

    wb.save(out_file)
    logger.info(f"Đã xuất báo cáo Event Log sang Excel thành công: {out_file}")
    return out_file
