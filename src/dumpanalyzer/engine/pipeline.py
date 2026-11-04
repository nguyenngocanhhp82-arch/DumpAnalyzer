"""Pipeline phân tích tập trung cho DumpAnalyzer.

Tập trung hoá toàn bộ luồng phân tích từ quét file dump, phân tích cdb/header,
truy vấn Event Log, đối chiếu cập nhật, thu thập bằng chứng và chấm điểm kết luận.
Dùng chung cho cả GUI (qua AnalysisWorker) và các tiến trình tự động khác,
đảm bảo tính nhất quán 100% giữa giao diện đồ họa và dòng lệnh CLI.
"""

from datetime import datetime
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from dumpanalyzer.analyzer.cdb_runner import build_crash_from_dump
from dumpanalyzer.collectors.drivers_updates import collect_recent_windows_updates
from dumpanalyzer.collectors.dump_finder import calculate_sha256, copy_dump_safely, find_dumps
from dumpanalyzer.collectors.eventlog import read_system_events
from dumpanalyzer.collectors.hardware import collect_machine_info
from dumpanalyzer.core.config import get_settings_path, load_settings
from dumpanalyzer.core.models import Crash, Evidence, MachineInfo
from dumpanalyzer.engine.correlator import Correlator
from dumpanalyzer.engine.rule_loader import load_all_rules, validate_rules_and_settings
from dumpanalyzer.engine.scorer import get_suspect_label_vi, score_machine_crashes
from dumpanalyzer.engine.verdict import generate_machine_finding
from dumpanalyzer.storage.db import Database

logger = logging.getLogger(__name__)


def run_analysis(
    source_type: str = "local",
    folder_path: Optional[str] = None,
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    db_path: Optional[str] = None,
    progress_cb: Optional[Callable[[int, str], None]] = None,
    status_cb: Optional[Callable[[str], None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Optional[Dict[str, Any]]:
    """Thực thi toàn bộ quy trình phân tích sự cố hệ thống.

    Args:
        source_type: Nguồn quét ('local' quét thư mục hệ thống hoặc 'folder' quét thư mục chỉ định).
        folder_path: Đường dẫn thư mục khi source_type == 'folder'.
        from_date: Lọc sự cố từ thời điểm (YYYY-MM-DD hoặc ISO string/datetime).
        to_date: Lọc sự cố đến thời điểm.
        db_path: Đường dẫn CSDL SQLite (mặc định lấy theo cấu hình).
        progress_cb: Callback cập nhật tiến trình (phần trăm 0-100, thông điệp hiển thị).
        status_cb: Callback cập nhật dòng trạng thái chi tiết.
        is_cancelled: Hàm kiểm tra xem người dùng đã bấm Huỷ hay chưa.

    Returns:
        Dict chứa đầy đủ dữ liệu phân tích nếu thành công, hoặc None nếu bị huỷ giữa chừng:
        {
            "machine_info": MachineInfo,
            "crashes": List[Crash],
            "finding": Finding,
            "evidences": List[Evidence],
            "suspect_ranking": List[Tuple[str, float]],
            "conflict_detected": bool,
            "patterns_matched": List[str],
        }
    """
    def _emit_progress(pct: int, msg: str) -> None:
        if progress_cb:
            try:
                progress_cb(pct, msg)
            except Exception:
                pass

    def _emit_status(msg: str) -> None:
        if status_cb:
            try:
                status_cb(msg)
            except Exception:
                pass

    def _check_cancelled() -> bool:
        if is_cancelled and is_cancelled():
            return True
        return False

    if _check_cancelled():
        _emit_progress(0, "Đã huỷ phân tích.")
        return None

    db = Database(db_path)
    try:
        _emit_progress(5, "Đang nạp và kiểm tra bộ quy tắc chẩn đoán...")

        # 1. Kiểm tra quy tắc & Nạp cấu hình
        rules_ok, rules_errs, _ = validate_rules_and_settings()
        if not rules_ok:
            logger.warning(f"Phát hiện cảnh báo quy tắc: {rules_errs}")

        rules = load_all_rules()
        settings = load_settings(get_settings_path())
        workspace_dir = Path(settings.get("workspace_dir", "workspace"))
        workspace_dir.mkdir(parents=True, exist_ok=True)

        if _check_cancelled():
            _emit_progress(0, "Đã huỷ phân tích.")
            return None

        # 2. Thu thập Machine Info
        _emit_progress(12, "Đang kiểm tra thông tin thiết bị...")
        machine_info: MachineInfo
        if source_type == "local":
            machine_info = collect_machine_info()
        else:
            folder_name = Path(folder_path).name if folder_path else "Thư mục dump"
            machine_info = MachineInfo(
                hostname=f"Thư mục: {folder_name}",
                model="Phân tích thư mục ngoại vi",
                cpu="N/A",
                bios="N/A",
                os_build="N/A",
            )
        machine_id = db.insert_machine(machine_info)

        if _check_cancelled():
            _emit_progress(0, "Đã huỷ phân tích.")
            return None

        # 3. Quét tìm dump files (Sửa lỗi 1: truyền list và xử lý an toàn)
        _emit_progress(20, "Đang tìm kiếm các file dump (.dmp)...")
        found_dumps: List[Dict[str, Any]] = []
        if source_type == "folder" and folder_path:
            found_dumps = find_dumps([folder_path], from_date=from_date, to_date=to_date)
        else:
            default_dumps = settings.get(
                "default_dump_paths",
                ["C:\\Windows\\Minidump", "C:\\Windows\\MEMORY.DMP"],
            )
            existing_paths = [str(p) for p in default_dumps if Path(p).exists()]
            if existing_paths:
                found_dumps = find_dumps(existing_paths, from_date=from_date, to_date=to_date)
            else:
                found_dumps = []

        total_dumps = len(found_dumps)
        _emit_status(f"Tìm thấy {total_dumps} file dump.")

        # 4. Phân tích các file dump (Sửa lỗi 2: lấy d_path từ item['path'])
        crashes: List[Crash] = []
        for idx, item in enumerate(found_dumps, start=1):
            if _check_cancelled():
                _emit_progress(0, "Đã huỷ phân tích.")
                return None

            pct = 25 + int((idx / max(total_dumps, 1)) * 40)
            d_path: Path = item["path"]
            d_name: str = item.get("filename", d_path.name)
            _emit_progress(pct, f"Đang phân tích dump {idx}/{total_dumps}: {d_name}")

            # Sao chép an toàn vào workspace
            try:
                sha = calculate_sha256(d_path)
                copied_path = copy_dump_safely(d_path, workspace_dir, file_sha256=sha)
            except Exception as e:
                logger.warning(f"Không thể sao chép dump {d_name}: {e}")
                continue

            if not copied_path or not sha:
                continue

            # Kiểm tra cache trong CSDL
            cached_dict = db.get_crash_by_sha256(sha)
            if cached_dict:
                cached_crash = Crash(**cached_dict)
                cached_crash.machine_id = machine_id
                crashes.append(cached_crash)
                continue

            # Phân tích sâu cdb hoặc header fallback
            crash = build_crash_from_dump(
                copied_path,
                settings=settings,
                machine_id=machine_id,
                sha256=sha,
            )
            c_id = db.insert_crash(crash)
            crash.id = c_id
            crashes.append(crash)

        if _check_cancelled():
            _emit_progress(0, "Đã huỷ phân tích.")
            return None

        # 5. Quét Event Log và tương quan (Sửa lỗi 3: correlate_recent_updates gọi 1 lần với list)
        _emit_progress(70, "Đang truy vấn Windows Event Log và tương quan sự kiện...")
        evidences: List[Evidence] = []
        if source_type == "local":
            events = read_system_events(from_date=from_date, to_date=to_date)
            updates = collect_recent_windows_updates(days=30)
            correlator = Correlator(window_minutes=settings.get("time_window_minutes", 10))

            # Phát hiện crash không có dump (chế độ log_only)
            detected_log_only = correlator.detect_log_only_crashes(crashes, events)
            for log_crash, _ in detected_log_only:
                log_crash.machine_id = machine_id
                existing = db.get_crash_by_sha256(log_crash.dump_sha256)
                if existing:
                    log_crash.id = existing["id"]
                else:
                    log_id = db.insert_crash(log_crash)
                    log_crash.id = log_id
                crashes.append(log_crash)

            # Ghép bằng chứng sự kiện cho từng vụ crash
            for c in crashes:
                evs = correlator.correlate_events_to_crash(c, events)
                for ev in evs:
                    ev.crash_id = c.id
                    ev_id = db.insert_evidence(ev)
                    ev.id = ev_id
                    evidences.append(ev)

            # Ghép bằng chứng cập nhật Windows 1 LẦN cho toàn bộ danh sách crash
            if crashes:
                upd_evs = correlator.correlate_recent_updates(crashes, updates)
                for ev in upd_evs:
                    ev_id = db.insert_evidence(ev)
                    ev.id = ev_id
                    evidences.append(ev)

        if _check_cancelled():
            _emit_progress(0, "Đã huỷ phân tích.")
            return None

        # 6. Chấm điểm & Xếp hạng nghi vấn (Sửa lỗi 4: score_machine_crashes nhận list tuple)
        _emit_progress(85, "Đang tính toán điểm xác suất và xếp hạng nghi vấn...")
        crashes_with_evs: List[Tuple[Crash, List[Evidence]]] = []
        for c in crashes:
            c_evs = [ev for ev in evidences if ev.crash_id == c.id]
            crashes_with_evs.append((c, c_evs))

        scored_result = score_machine_crashes(crashes_with_evs, rules, settings)
        raw_scores = scored_result.get("suspect_scores", [])
        suspect_ranking: List[Dict[str, Any]] = []
        for item in raw_scores:
            if isinstance(item, dict):
                suspect_ranking.append(item)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                susp, score = item[0], float(item[1])
                suspect_ranking.append({
                    "suspect": susp,
                    "label": get_suspect_label_vi(susp),
                    "percentage": score,
                    "score": score,
                })

        conflict_detected = scored_result.get("is_conflicted", False)
        patterns_matched = scored_result.get("patterns_matched", [])

        if _check_cancelled():
            _emit_progress(0, "Đã huỷ phân tích.")
            return None

        # 7. Sinh kết luận Finding (Sửa lỗi 5: generate_machine_finding đúng chữ ký)
        _emit_progress(95, "Đang tổng hợp khuyến nghị xử lý và hoàn thiện báo cáo...")
        finding = generate_machine_finding(
            machine_id=machine_id,
            scored_result=scored_result,
            rules=rules,
        )

        # Xử lý trường hợp không tìm thấy dump nào (Mục 3.4.5)
        if not crashes:
            finding.rationale = (
                "Không tìm thấy file dump nào trên hệ thống hoặc trong thư mục đã chọn. "
                "Máy có thể chưa được bật tính năng ghi dump (CrashDumpEnabled = 0 hoặc cấu hình bộ nhớ ảo chưa chuẩn)."
            )

        setattr(finding, "suspect_ranking", suspect_ranking)
        db.insert_finding(finding)

        _emit_progress(100, "Hoàn tất phân tích sự cố thành công!")

        payload = {
            "machine_info": machine_info,
            "crashes": crashes,
            "finding": finding,
            "evidences": evidences,
            "suspect_ranking": suspect_ranking,
            "conflict_detected": conflict_detected,
            "patterns_matched": patterns_matched,
        }
        return payload

    finally:
        db.close()
