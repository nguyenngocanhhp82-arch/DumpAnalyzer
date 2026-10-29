"""Luồng xử lý nền (Background Worker) cho PySide6 GUI.

Đảm bảo toàn bộ quá trình quét dump, chạy cdb, truy vấn Event Log và chấm điểm
diễn ra trong QThread riêng biệt, không bao giờ làm treo hoặc đơ giao diện người dùng.
Hỗ trợ thanh tiến trình (progress bar), cập nhật thông báo và nút Huỷ an toàn.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from PySide6.QtCore import QThread, Signal

from dumpanalyzer.analyzer.cdb_runner import build_crash_from_dump
from dumpanalyzer.analyzer.header_parser import parse_dump_header
from dumpanalyzer.collectors.drivers_updates import collect_recent_windows_updates
from dumpanalyzer.collectors.dump_finder import calculate_sha256, copy_dump_safely, find_dumps
from dumpanalyzer.collectors.eventlog import read_system_events
from dumpanalyzer.collectors.hardware import collect_machine_info
from dumpanalyzer.core.config import get_settings_path, load_settings
from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.engine.correlator import Correlator
from dumpanalyzer.engine.rule_loader import load_all_rules, validate_rules_and_settings
from dumpanalyzer.engine.scorer import score_machine_crashes
from dumpanalyzer.engine.verdict import generate_machine_finding
from dumpanalyzer.storage.db import Database

logger = logging.getLogger(__name__)


class AnalysisWorker(QThread):
    """QThread thực hiện quy trình phân tích toàn diện trong nền."""

    # Tín hiệu phát ra cho giao diện
    progress = Signal(int, str)           # (Phần trăm 0-100, Thông điệp hiển thị)
    status_message = Signal(str)          # Thông báo chi tiết
    finished = Signal(dict)               # Trả về kết quả phân tích
    error = Signal(str)                   # Báo lỗi nghiêm trọng

    def __init__(
        self,
        source_type: str = "local",       # 'local' hoặc 'folder'
        folder_path: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        db_path: Optional[str] = None,
        parent: Optional[Any] = None,
    ):
        super().__init__(parent)
        self.source_type = source_type
        self.folder_path = folder_path
        self.from_date = from_date
        self.to_date = to_date
        self.db_path = db_path
        self._is_cancelled = False

    def cancel(self) -> None:
        """Kích hoạt cờ huỷ để luồng dừng an toàn."""
        self._is_cancelled = True
        logger.info("Yêu cầu huỷ quá trình phân tích từ người dùng.")

    def run(self) -> None:
        """Hàm thực thi chính trong luồng riêng biệt."""
        try:
            self._is_cancelled = False
            self.progress.emit(5, "Đang nạp và kiểm tra bộ quy tắc chẩn đoán...")

            # 1. Khởi tạo CSDL & Kiểm tra quy tắc
            db = Database(self.db_path)
            rules_ok, rules_errs, _ = validate_rules_and_settings()
            if not rules_ok:
                logger.warning(f"Phát hiện cảnh báo quy tắc: {rules_errs}")

            rules = load_all_rules()
            settings = load_settings(get_settings_path())
            workspace_dir = Path(settings.get("workspace_dir", "workspace"))
            workspace_dir.mkdir(parents=True, exist_ok=True)

            if self._is_cancelled:
                db.close()
                self.progress.emit(0, "Đã huỷ phân tích.")
                return

            # 2. Thu thập Machine Info
            self.progress.emit(12, "Đang kiểm tra thông tin thiết bị...")
            machine_info = None
            machine_id = None
            if self.source_type == "local":
                machine_info = collect_machine_info()
                machine_id = db.insert_machine(machine_info)
            else:
                folder_name = Path(self.folder_path).name if self.folder_path else "Thu mục dump"
                machine_info = MachineInfo(
                    hostname=f"Thu mục: {folder_name}",
                    model="Phân tích thư mục ngoại vi",
                    cpu="N/A",
                    bios="N/A",
                    os_build="N/A",
                )
                machine_id = db.insert_machine(machine_info)

            # 3. Quét tìm dump files
            self.progress.emit(20, "Đang tìm kiếm các file dump (.dmp)...")
            dump_paths: List[Path] = []
            if self.source_type == "folder" and self.folder_path:
                dump_paths = find_dumps(self.folder_path, self.from_date, self.to_date)
            else:
                default_dumps = settings.get("default_dump_paths", ["C:\\Windows\\Minidump", "C:\\Windows\\MEMORY.DMP"])
                for p in default_dumps:
                    p_obj = Path(p)
                    if p_obj.exists():
                        dump_paths.extend(find_dumps(p_obj, self.from_date, self.to_date))

            # 4. Phân tích các file dump
            crashes: List[Crash] = []
            total_dumps = len(dump_paths)
            self.status_message.emit(f"Tìm thấy {total_dumps} file dump.")

            for idx, d_path in enumerate(dump_paths, start=1):
                if self._is_cancelled:
                    db.close()
                    self.progress.emit(0, "Đã huỷ phân tích.")
                    return

                pct = 25 + int((idx / max(total_dumps, 1)) * 40)
                self.progress.emit(pct, f"Đang phân tích dump {idx}/{total_dumps}: {d_path.name}")

                # Copy an toàn sang workspace
                try:
                    sha = calculate_sha256(d_path)
                    copied_path = copy_dump_safely(d_path, workspace_dir, file_sha256=sha)
                except Exception as e:
                    logger.warning(f"Không thể copy dump {d_path.name}: {e}")
                    continue

                if not copied_path or not sha:
                    continue

                # Kiểm tra cache
                cached_dict = db.get_crash_by_sha256(sha)
                if cached_dict:
                    cached_crash = Crash(**cached_dict)
                    cached_crash.machine_id = machine_id
                    crashes.append(cached_crash)
                    continue

                # Phân tích sâu cdb hoặc header fallback
                crash = build_crash_from_dump(copied_path, settings=settings, machine_id=machine_id, sha256=sha)
                crash_id = db.insert_crash(crash)
                crash.id = crash_id
                crashes.append(crash)

            if self._is_cancelled:
                db.close()
                self.progress.emit(0, "Đã huỷ phân tích.")
                return

            # 5. Quét Event Log và tương quan (nếu là máy cục bộ)
            self.progress.emit(70, "Đang truy vấn Windows Event Log và tương quan sự kiện...")
            evidences: List[Evidence] = []
            if self.source_type == "local":
                events = read_system_events(from_date=self.from_date, to_date=self.to_date)
                updates = collect_recent_windows_updates(days=30)
                correlator = Correlator(window_minutes=settings.get("time_window_minutes", 10))

                # Phát hiện crash log_only
                detected_log_only = correlator.detect_log_only_crashes(crashes, events)
                for log_crash, _ in detected_log_only:
                    log_crash.machine_id = machine_id
                    log_crash_id = db.insert_crash(log_crash)
                    log_crash.id = log_crash_id
                    crashes.append(log_crash)

                # Ghép bằng chứng cho từng vụ crash
                for c in crashes:
                    evs = correlator.correlate_events_to_crash(c, events)
                    upd_evs = correlator.correlate_recent_updates(c, updates)
                    all_evs = evs + upd_evs
                    for ev in all_evs:
                        ev.crash_id = c.id
                        db.insert_evidence(ev)
                        evidences.append(ev)

            if self._is_cancelled:
                db.close()
                self.progress.emit(0, "Đã huỷ phân tích.")
                return

            # 6. Chấm điểm & Xếp hạng nguyên nhân
            self.progress.emit(85, "Đang tính toán điểm xác suất và xếp hạng nghi vấn...")
            top_suspect, top_score, confidence, suspect_ranking, conflict_detected, patterns_matched = score_machine_crashes(
                crashes=crashes,
                rules=rules,
                evidences=evidences,
            )

            # 7. Sinh kết luận (Finding)
            self.progress.emit(95, "Đang tổng hợp khuyến nghị xử lý và hoàn thiện báo cáo...")
            finding = generate_machine_finding(
                crashes=crashes,
                rules=rules,
                top_suspect=top_suspect,
                top_score=top_score,
                confidence=confidence,
                conflict_detected=conflict_detected,
                patterns_matched=patterns_matched,
                machine_id=machine_id,
            )
            # Gắn suspect_ranking vào finding
            setattr(finding, "suspect_ranking", suspect_ranking)

            # Lưu finding vào DB
            db.insert_finding(finding)
            db.close()

            self.progress.emit(100, "Hoàn tất phân tích sự cố thành công!")
            payload = {
                "machine_info": machine_info,
                "crashes": crashes,
                "finding": finding,
                "evidences": evidences,
                "suspect_ranking": suspect_ranking,
                "conflict_detected": conflict_detected,
                "patterns_matched": patterns_matched,
            }
            self.finished.emit(payload)

        except Exception as e:
            logger.exception("Lỗi trong quá trình phân tích nền:")
            self.error.emit(f"Đã xảy ra lỗi khi phân tích: {str(e)}")
