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

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import json
import re
import yaml

from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.core.config import get_project_root, load_settings
from dumpanalyzer.core.timeutil import parse_to_utc
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.analyzer.header_parser import lookup_bugcheck_name

logger = get_logger("correlator")


def _extract_event_6008_time(ev: Dict[str, Any]) -> Optional[datetime]:
    """Trích xuất thời điểm tắt máy bất thường từ Event 6008."""
    ed = ev.get("event_data")
    if isinstance(ed, dict):
        if "ShutdownTime" in ed and ed["ShutdownTime"]:
            dt = parse_to_utc(str(ed["ShutdownTime"]))
            if dt:
                return dt
        for val in ed.values():
            if isinstance(val, str) and len(val) >= 10:
                dt = parse_to_utc(val)
                if dt:
                    return dt
    msg = ev.get("raw_message", "")
    if msg:
        iso_match = re.search(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b", msg)
        if iso_match:
            dt = parse_to_utc(iso_match.group(1))
            if dt:
                return dt
    return None



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

    def get_event_rule_info(self, provider: str, event_id: int) -> Dict[str, Any]:
        """Tra cứu cấu hình quy tắc (mô tả, strength, polarity, group_id) từ event_rules.yaml."""
        for r in self.event_rules:
            if r.get("source", "").lower() in provider.lower():
                if event_id in r.get("ids", []):
                    return {
                        "description": r.get("description", f"Sự kiện {provider} ID {event_id}"),
                        "strength": r.get("strength", "weak"),
                        "polarity": r.get("polarity", "support"),
                        "group_id": r.get("group_id", f"eventlog_{event_id}"),
                    }
        return {
            "description": f"Sự kiện từ {provider} (ID {event_id})",
            "strength": "weak",
            "polarity": "support",
            "group_id": f"eventlog_{event_id}",
        }

    def get_event_summary(self, provider: str, event_id: int) -> str:
        """Tra cứu mô tả ngắn gọn bằng tiếng Việt cho sự kiện từ event_rules.yaml."""
        return self.get_event_rule_info(provider, event_id)["description"]

    def correlate_events_to_crash(
        self,
        crash: Crash,
        all_events: List[Dict[str, Any]],
        app_events: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Evidence]:
        """
        Tìm các sự kiện xảy ra trong cửa sổ [crash_time - window_minutes, crash_time + 2 phút].
        Tạo danh sách đối tượng Evidence gắn với crash.id (bao gồm strength, polarity, group_id).
        """
        if not crash.crash_time_utc:
            return []

        crash_dt = parse_to_utc(crash.crash_time_utc)
        if not crash_dt:
            return []

        start_dt = crash_dt - timedelta(minutes=self.window_minutes)
        end_dt = crash_dt + timedelta(minutes=2)  # Cho phép dung sai 2 phút ghi log

        # Nếu là log_only: mở rộng cửa sổ đến thời điểm Event 41 (thời điểm reboot) + 2 phút
        if crash.analyzed_by == "log_only" or crash.crash_time_source in ("eventlog_6008", "estimated", "kp41"):
            candidate_kps = []
            for ev in all_events:
                if ev.get("event_id") == 41 and "Kernel-Power" in ev.get("provider", ""):
                    ev_t = ev.get("time_created_utc")
                    if ev_t:
                        ev_dt = parse_to_utc(ev_t)
                        if ev_dt and ev_dt >= crash_dt - timedelta(minutes=1):
                            candidate_kps.append(ev_dt)
            if candidate_kps:
                kp_dt = min(candidate_kps, key=lambda t: (t - crash_dt).total_seconds())
                end_dt = max(end_dt, kp_dt + timedelta(minutes=2))

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

                rule_info = self.get_event_rule_info(prov, eid)
                summary = rule_info["description"]
                strength = rule_info["strength"]
                polarity = rule_info["polarity"]
                group_id = rule_info["group_id"]

                detail = ev.get("raw_message", "")
                if not detail and ev.get("event_data"):
                    detail = json.dumps(ev.get("event_data"), ensure_ascii=False)

                # Làm giàu chi tiết cho Kernel-Power 41 (SleepInProgress, PowerButtonTimestamp)
                if eid == 41 and "kp41_info" in ev:
                    kp = ev["kp41_info"]
                    detail = (
                        f"Kernel-Power 41: BugcheckCode={kp.get('bugcheck_code', '0x0')}, "
                        f"SleepInProgress={kp.get('sleep_in_progress', '0')}, "
                        f"PowerButtonTimestamp={kp.get('power_button_timestamp', '0')}. "
                        + detail
                    )

                evidence = Evidence(
                    crash_id=crash.id,
                    kind="eventlog",
                    source=prov,
                    event_id=eid,
                    time_utc=ev_time_str,
                    summary=summary,
                    detail=detail[:500],  # Cắt ngắn để lưu gọn
                    strength=strength,
                    polarity=polarity,
                    group_id=group_id,
                )
                evidences.append(evidence)

        # Xử lý Application Log (Application Error 1000) trong cửa sổ 24h quanh crash
        if app_events:
            app_start = crash_dt - timedelta(hours=24)
            window_apps = set()
            for aev in app_events:
                at_str = aev.get("time_created_utc")
                if at_str:
                    adt = parse_to_utc(at_str)
                    if adt and app_start <= adt <= end_dt:
                        info = aev.get("app_crash_info") or {}
                        aname = info.get("app_name") or aev.get("event_data", {}).get("AppName") or aev.get("event_data", {}).get("param1")
                        if aname:
                            window_apps.add(str(aname).strip().lower())

            if len(window_apps) >= 3:
                app_list_str = ", ".join(sorted(window_apps)[:5])
                evidences.append(
                    Evidence(
                        crash_id=crash.id,
                        kind="eventlog",
                        source="Application Error",
                        event_id=1000,
                        time_utc=crash.crash_time_utc or "",
                        summary=f"Phát hiện {len(window_apps)} ứng dụng khác nhau ({app_list_str}) bị sập ngẫu nhiên",
                        detail=f"Có {len(window_apps)} ứng dụng khác nhau sập trong cửa sổ sự cố: {app_list_str}. Dấu hiệu này thường chỉ ra bộ nhớ RAM bị lỗi hoặc chập chờn.",
                        strength="medium",
                        polarity="support",
                        group_id="eventlog_app_crash",
                    )
                )

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

            # Xác định thời điểm và nguồn thời gian sập (Nhóm D)
            # Thứ tự ưu tiên:
            # 1. Event 6008 gần thời điểm reboot kp_dt
            # 2. Ước lượng bằng sự kiện cuối cùng trước thời điểm khởi động
            # 3. Fallback dùng chính thời điểm Event 41
            crash_time_utc = kp_time_str
            crash_time_source = "kp41"

            # 1. Kiểm tra Event 6008
            found_6008 = False
            for ev in all_events:
                if ev.get("event_id") == 6008:
                    ev_t_str = ev.get("time_created_utc")
                    if ev_t_str:
                        ev_dt = parse_to_utc(ev_t_str)
                        if ev_dt and abs((ev_dt - kp_dt).total_seconds()) <= 600:
                            s_time = _extract_event_6008_time(ev)
                            if s_time:
                                crash_time_utc = s_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                                crash_time_source = "eventlog_6008"
                                if ev not in matched_events:
                                    matched_events.append(ev)
                                found_6008 = True
                                break

            # 2. Nếu không có 6008, tìm sự kiện cuối cùng trước boot
            if not found_6008:
                boot_times = [kp_dt]
                for ev in all_events:
                    eid = ev.get("event_id")
                    prov = ev.get("provider", "")
                    if eid in (6005, 12) or (eid == 41 and "Kernel-Power" in prov):
                        ev_t_str = ev.get("time_created_utc")
                        if ev_t_str:
                            ev_dt = parse_to_utc(ev_t_str)
                            if ev_dt and abs((ev_dt - kp_dt).total_seconds()) <= 300:
                                boot_times.append(ev_dt)
                boot_start_dt = min(boot_times)

                pre_boot_events = []
                for ev in all_events:
                    eid = ev.get("event_id")
                    if eid in (41, 6005, 12):
                        continue
                    ev_t_str = ev.get("time_created_utc")
                    if ev_t_str:
                        ev_dt = parse_to_utc(ev_t_str)
                        if ev_dt and (boot_start_dt - timedelta(hours=24) <= ev_dt < boot_start_dt - timedelta(seconds=15)):
                            pre_boot_events.append((ev_dt, ev_t_str))

                if pre_boot_events:
                    latest_dt, latest_str = max(pre_boot_events, key=lambda x: x[0])
                    crash_time_utc = latest_str
                    crash_time_source = "estimated"

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
                crash_time_utc=crash_time_utc,
                crash_time_source=crash_time_source,
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
                        strength="medium",
                        polarity="support",
                        group_id="windows_update",
                    )
                )


        return evidences
