"""
Module tương quan thời gian và ngữ cảnh hệ thống (Correlator).
Nhiệm vụ:
1. Ghép các sự kiện Event Log trong cửa sổ 10 phút trước thời điểm sập vào từng Crash.
2. Gộp Event 41 và Event 1001 của cùng một lần sập thành một vụ sập duy nhất.
3. Nhận diện các vụ sập không có dump (chế độ log_only):
   - Event 41 có BugcheckCode != 0: lấy mã lỗi hex từ log.
   - Event 41 có BugcheckCode == 0: sập nguồn, quá nhiệt hoặc treo cứng không có BSOD.
4. Gắn các sự kiện cập nhật Windows / cài đặt phần mềm trong 7 ngày trước crash đầu tiên.
5. Tạo và lưu các bản ghi Evidence có liên kết trực tiếp với Crash.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json
import yaml

from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.core.config import get_project_root, load_settings
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.analyzer.header_parser import lookup_bugcheck_name

logger = get_logger("correlator")


def load_event_rules() -> List[Dict[str, Any]]:
    """Tải danh sách quy tắc sự kiện từ event_rules.yaml."""
    rules_file = get_project_root() / "config" / "rules" / "event_rules.yaml"
    if not rules_file.exists():
        return []

    try:
        with open(rules_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict) and "events" in data:
                return data["events"]
    except Exception as e:
        logger.warning(f"Lỗi đọc event_rules.yaml: {e}")

    return []


class Correlator:
    """Bộ điều phối tương quan thời gian giữa Dump, Event Log và Cập nhật."""

    def __init__(self, window_minutes: Optional[int] = None, update_days: Optional[int] = None):
        settings = load_settings()
        self.window_minutes = window_minutes or settings.get("event_window_minutes", 10)
        self.update_days = update_days or settings.get("update_history_days", 7)
        self.event_rules = load_event_rules()

    def get_event_summary(self, provider: str, event_id: int) -> str:
        """Tra cứu mô tả ngắn gọn bằng tiếng Việt cho sự kiện từ event_rules.yaml."""
        for r in self.event_rules:
            if r.get("source", "").lower() in provider.lower():
                if event_id in r.get("ids", []):
                    return r.get("description", f"Sự kiện {provider} ID {event_id}")
        return f"Sự kiện từ {provider} (ID {event_id})"

    def correlate_events_to_crash(
        self,
        crash: Crash,
        all_events: List[Dict[str, Any]],
    ) -> List[Evidence]:
        """
        Tìm các sự kiện xảy ra trong cửa sổ [crash_time - window_minutes, crash_time + 2 phút].
        Tạo danh sách đối tượng Evidence gắn với crash.id.
        """
        if not crash.crash_time_utc:
            return []

        crash_dt = parse_to_utc(crash.crash_time_utc)
        if not crash_dt:
            return []

        start_dt = crash_dt - timedelta(minutes=self.window_minutes)
        end_dt = crash_dt + timedelta(minutes=2)  # Cho phép dung sai 2 phút ghi log

        evidences: List[Evidence] = []

        for ev in all_events:
            ev_time_str = ev.get("time_created_utc")
            if not ev_time_str:
                continue

            ev_dt = parse_to_utc(ev_time_str)
            if not ev_dt:
                continue

            # Kiểm tra xem sự kiện có rơi vào cửa sổ thời gian không
            if start_dt <= ev_dt <= end_dt:
                eid = ev.get("event_id", 0)
                prov = ev.get("provider", "")

                # Bỏ qua sự kiện tắt máy có chủ đích (User32 1074) nếu có
                if eid == 1074:
                    continue

                summary = self.get_event_summary(prov, eid)
                detail = ev.get("raw_message", "")
                if not detail and ev.get("event_data"):
                    detail = json.dumps(ev.get("event_data"), ensure_ascii=False)

                kind = "eventlog"

                evidence = Evidence(
                    crash_id=crash.id,
                    kind=kind,
                    source=prov,
                    event_id=eid,
                    time_utc=ev_time_str,
                    summary=summary,
                    detail=detail[:500],  # Cắt ngắn để lưu gọn
                )
                evidences.append(evidence)

        return evidences

    def detect_log_only_crashes(
        self,
        existing_crashes: List[Crash],
        all_events: List[Dict[str, Any]],
    ) -> List[Tuple[Crash, List[Dict[str, Any]]]]:
        """
        Phát hiện các vụ sập hệ thống KHÔNG CÓ DUMP (chế độ log_only):
        - Quét tìm Kernel-Power Event 41 và WER Event 1001.
        - Gộp 41 và 1001 cùng một thời điểm thành 1 crash duy nhất.
        - Nếu quanh thời điểm đó (dung sai 10 phút) đã có Crash từ file dump thì bỏ qua (tránh trùng).
        - Nếu chưa có: tạo Crash mới với dump_type='none', analyzed_by='log_only'.
        """
        # Thu thập các mốc thời gian của crash dump đã biết
        existing_times = []
        for c in existing_crashes:
            if c.crash_time_utc:
                dt = parse_to_utc(c.crash_time_utc)
                if dt:
                    existing_times.append(dt)

        # Lọc danh sách Event 41 và Event 1001
        kp_events = [e for e in all_events if e.get("event_id") == 41 and "Kernel-Power" in e.get("provider", "")]
        wer_events = [e for e in all_events if e.get("event_id") == 1001]

        detected: List[Tuple[Crash, List[Dict[str, Any]]]] = []
        handled_event_times = set()

        for kp in kp_events:
            kp_time_str = kp.get("time_created_utc")
            if not kp_time_str:
                continue

            kp_dt = parse_to_utc(kp_time_str)
            if not kp_dt:
                continue

            # Kiểm tra xem đã có crash dump nào trùng mốc này chưa
            is_duplicate = False
            for ex_dt in existing_times:
                if abs((kp_dt - ex_dt).total_seconds()) <= self.window_minutes * 60:
                    is_duplicate = True
                    break

            if is_duplicate:
                continue

            # Tránh xử lý lặp lại event cùng phút
            time_key = kp_time_str[:16]
            if time_key in handled_event_times:
                continue
            handled_event_times.add(time_key)

            kp_info = kp.get("kp41_info", {})
            bc_code = kp_info.get("bugcheck_code", "0x0")
            p1 = kp_info.get("p1", "0x0")
            p2 = kp_info.get("p2", "0x0")
            p3 = kp_info.get("p3", "0x0")
            p4 = kp_info.get("p4", "0x0")

            # Tìm xem có Event 1001 nào đi kèm trong vòng 10 phút sau sập không
            matched_events = [kp]
            for wer in wer_events:
                wer_time = wer.get("time_created_utc")
                if wer_time:
                    wer_dt = parse_to_utc(wer_time)
                    if wer_dt and 0 <= (wer_dt - kp_dt).total_seconds() <= self.window_minutes * 60:
                        matched_events.append(wer)
                        wer_info = wer.get("wer1001_info", {})
                        if wer_info.get("bugcheck_code") and bc_code in ("0x0", ""):
                            bc_code = wer_info.get("bugcheck_code")
                            p1 = wer_info.get("p1", p1)
                            p2 = wer_info.get("p2", p2)
                            p3 = wer_info.get("p3", p3)
                            p4 = wer_info.get("p4", p4)

            # Đặt tên lỗi
            if bc_code and bc_code != "0x0":
                bc_name = lookup_bugcheck_name(bc_code)
            else:
                bc_code = ""
                bc_name = "Tắt máy/Mất nguồn đột ngột (Không có BSOD)"

            log_crash = Crash(
                dump_path="",
                dump_sha256=f"log_only_{kp_time_str.replace(':', '').replace('-', '')}",
                dump_type="none",
                crash_time_utc=kp_time_str,
                bugcheck_code=bc_code,
                bugcheck_name=bc_name,
                p1=p1,
                p2=p2,
                p3=p3,
                p4=p4,
                analyzed_by="log_only",
            )

            detected.append((log_crash, matched_events))

        return detected

    def correlate_recent_updates(
        self,
        crashes: List[Crash],
        updates: List[Dict[str, Any]],
    ) -> List[Evidence]:
        """
        Tìm các bản cập nhật Windows hoặc phần mềm diễn ra trong vòng 7 ngày
        trước thời điểm sập đầu tiên trong danh sách crash.
        """
        if not crashes or not updates:
            return []

        # Tìm crash đầu tiên theo thời gian
        valid_crashes = [c for c in crashes if c.crash_time_utc]
        if not valid_crashes:
            return []

        valid_crashes.sort(key=lambda x: x.crash_time_utc)
        first_crash = valid_crashes[0]
        first_dt = parse_to_utc(first_crash.crash_time_utc)
        if not first_dt:
            return []

        start_window = first_dt - timedelta(days=self.update_days)
        evidences: List[Evidence] = []

        for up in updates:
            up_time_str = up.get("installed_time_utc")
            if not up_time_str:
                continue

            up_dt = parse_to_utc(up_time_str)
            if not up_dt:
                continue

            if start_window <= up_dt <= first_dt:
                hotfix_id = up.get("hotfix_id", "Update")
                desc = up.get("description", "Cập nhật hệ thống")
                evidences.append(
                    Evidence(
                        crash_id=first_crash.id,
                        kind="update",
                        source="WindowsUpdate",
                        time_utc=up_time_str,
                        summary=f"Cài đặt bản cập nhật {hotfix_id} trong 7 ngày trước lần sập đầu tiên",
                        detail=f"{desc} ({hotfix_id}) cài đặt lúc {up_time_str}",
                    )
                )

        return evidences
