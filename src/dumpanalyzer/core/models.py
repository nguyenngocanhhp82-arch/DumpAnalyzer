"""
Định nghĩa các mô hình dữ liệu lõi (Data Models) cho DumpAnalyzer.
Bao gồm: Thông tin máy, Vụ sập (Crash), Bằng chứng (Evidence), Kết luận (Finding).
"""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class MachineInfo:
    """Thông tin phần cứng và hệ điều hành của máy tính gặp sự cố."""
    id: Optional[int] = None
    hostname: str = ""
    model: str = ""
    bios: str = ""
    cpu: str = ""
    os_build: str = ""


@dataclass
class Crash:
    """
    Thông tin một vụ sập hệ thống (BSOD hoặc tắt đột ngột).
    Mỗi file dump hoặc sự kiện Kernel-Power 41 (BugcheckCode=0) sẽ tạo 1 Crash.
    """
    id: Optional[int] = None
    machine_id: Optional[int] = None
    dump_path: str = ""              # Đường dẫn file dump đã copy vào thư mục làm việc
    dump_sha256: str = ""            # Khóa mã băm SHA256 dùng để kiểm tra cache trùng lặp
    dump_type: str = "mini"          # 'mini', 'kernel', 'full', hoặc 'none' (khi không có file dump)
    crash_time_utc: Optional[str] = None  # Thời gian sập chuẩn hoá định dạng ISO-8601 UTC
    bugcheck_code: str = ""          # Mã hex chuẩn hoá (ví dụ: '0x124', '0x133')
    bugcheck_name: str = ""          # Tên chuẩn (ví dụ: 'WHEA_UNCORRECTABLE_ERROR')
    p1: str = ""                     # Tham số BugCheck Parameter 1
    p2: str = ""                     # Tham số BugCheck Parameter 2
    p3: str = ""                     # Tham số BugCheck Parameter 3
    p4: str = ""                     # Tham số BugCheck Parameter 4
    image_name: str = ""             # Tên image/driver liên quan (từ cdb)
    module_name: str = ""            # Tên module gây lỗi
    process_name: str = ""           # Tên tiến trình đang chạy khi sập
    failure_bucket_id: str = ""      # Chuỗi bucket ID từ Microsoft WinDbg
    uptime_seconds: int = 0          # Thời gian máy chạy trước khi sập (giây)
    cdb_raw_output: str = ""         # Toàn bộ nội dung text xuất ra từ cdb !analyze -v
    analyzed_by: str = "none"        # 'cdb', 'header_only', hoặc 'none'
    crash_time_source: str = "unknown"  # 'header', 'mtime', 'cdb', 'eventlog_6008', 'estimated', 'kp41'
    suspect_driver: str = ""         # Driver nghi vấn tìm thấy trong stack trace (từ cdb)
    extra_json: str = "{}"           # Dữ liệu mở rộng JSON (errrec, chkimg, driver_age)


@dataclass
class Evidence:
    """
    Một bằng chứng cụ thể liên kết với vụ sập (Crash).
    Có thể đến từ Dump, Windows Event Log, SMART ổ cứng, hoặc lịch sử cập nhật.
    """
    id: Optional[int] = None
    crash_id: Optional[int] = None
    kind: str = "eventlog"           # 'dump', 'eventlog', 'smart', 'update', 'driver', 'thermal', 'sysinfo', 'hwtest'
    source: str = ""                 # Ví dụ: 'Microsoft-Windows-WHEA-Logger', 'Disk', 'cdb'
    event_id: Optional[int] = None   # Event ID trong Event Log (ví dụ: 41, 1001, 7)
    time_utc: str = ""               # Thời điểm diễn ra sự kiện (UTC)
    summary: str = ""                # Tóm tắt ngắn gọn sự kiện bằng tiếng Việt
    detail: str = ""                 # Chi tiết kỹ thuật hoặc nội dung mô tả đầy đủ
    strength: str = "weak"           # 'strong', 'medium', 'weak'
    polarity: str = "support"        # 'support' (ủng hộ), 'refute' (phản bác)
    group_id: str = ""               # Nhóm bằng chứng độc lập (ví dụ: 'cdb_stack', 'eventlog_disk', ...)


@dataclass
class Finding:
    """
    Kết luận chẩn đoán được suy luận từ Rule Engine.
    Mỗi kết luận có mức điểm, bằng chứng chứng minh và hành động đề xuất.
    """
    id: Optional[int] = None
    scope: str = "crash"             # 'crash' (kết luận 1 vụ sập) hoặc 'machine' (tổng thể máy)
    crash_id: Optional[int] = None
    machine_id: Optional[int] = None
    suspect: str = "unknown"         # 'ram', 'storage', 'gpu', 'psu', 'thermal', 'cpu', 'driver:<tên>', 'update', 'unknown'
    score: float = 0.0               # Thang điểm 0 - 100
    confidence: str = "thấp"         # 'thấp', 'trung bình', 'cao'
    rationale: str = ""              # Lời giải thích nguyên nhân rõ ràng bằng tiếng Việt
    evidence_ids: List[int] = field(default_factory=list)  # Danh sách ID các Evidence dẫn chứng
    next_steps: List[str] = field(default_factory=list)    # Các bước kiểm tra theo thứ tự từ dễ đến khó
    suspicion_share: float = 0.0     # Tỷ trọng nghi ngờ (%)
    confidence_rationale: str = ""   # Giải thích vì sao gắn nhãn độ tin cậy này

