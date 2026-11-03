"""
Module phân tích tổng quan đội máy (Fleet Analysis) - Phần 2.3.
Gom các vụ sập hệ thống trên toàn bộ máy tính trong cơ sở dữ liệu theo:
1. FAILURE_BUCKET_ID từ Microsoft WinDbg
2. suspect_driver / module bên thứ ba
Nhận diện các nguyên nhân lỗi lan rộng trên >= N máy trong vòng D ngày.
Sinh bằng chứng mức vừa (medium strength) ủng hộ nhóm driver/phần mềm.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from collections import defaultdict

from dumpanalyzer.core.config import load_settings
from dumpanalyzer.core.models import Evidence
from dumpanalyzer.storage.db import Database



def analyze_fleet_crashes(
    db: Database,
    settings: Optional[Dict[str, Any]] = None,
    rules: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Phân tích đội máy:
    Gom crash trong D ngày (fleet_window_days, mặc định 30) theo failure_bucket_id và suspect_driver.
    Lọc các mẫu hình xuất hiện trên >= N máy (fleet_min_machines, mặc định 3).
    """
    settings = settings or load_settings()
    sys_rules = (rules or {}).get("system_rules", {})
    fleet_cfg = sys_rules.get("fleet_rules", {})

    min_machines = int(
        fleet_cfg.get("min_machines")
        or settings.get("fleet_min_machines", 3)
    )
    window_days = int(
        fleet_cfg.get("window_days")
        or settings.get("fleet_window_days", 30)
    )

    now = datetime.now(timezone.utc)
    from_date = (now - timedelta(days=window_days)).isoformat()

    all_crashes = db.get_crashes_by_machine(machine_id=None, from_date=from_date)

    # Gom theo Bucket ID và suspect driver
    bucket_machines = defaultdict(set)
    bucket_crashes = defaultdict(list)
    driver_machines = defaultdict(set)
    driver_crashes = defaultdict(list)

    machine_cache: Dict[int, str] = {}

    for c in all_crashes:
        m_id = c.get("machine_id") or 0
        if m_id not in machine_cache and m_id > 0:
            conn = db._get_connection()
            cur = conn.execute("SELECT hostname FROM machine WHERE id = ?", (m_id,))
            row = cur.fetchone()
            machine_cache[m_id] = row["hostname"] if row else f"Machine#{m_id}"

        m_name = machine_cache.get(m_id, f"Machine#{m_id}")

        b_id = (c.get("failure_bucket_id") or "").strip()
        if b_id and b_id.upper() not in ("N/A", "UNKNOWN", "NONE"):
            bucket_machines[b_id].add(m_name)
            bucket_crashes[b_id].append(c)

        drv = (c.get("suspect_driver") or "").strip().lower()
        if drv and drv not in ("nt", "ntoskrnl.exe", "unknown", ""):
            driver_machines[drv].add(m_name)
            driver_crashes[drv].append(c)

    # Lọc nhóm xuất hiện trên >= min_machines
    flagged_buckets = []
    for b_id, m_set in bucket_machines.items():
        if len(m_set) >= min_machines:
            flagged_buckets.append({
                "bucket_id": b_id,
                "machine_count": len(m_set),
                "machines": sorted(list(m_set)),
                "crash_count": len(bucket_crashes[b_id]),
            })

    flagged_drivers = []
    for drv, m_set in driver_machines.items():
        if len(m_set) >= min_machines:
            flagged_drivers.append({
                "driver": drv,
                "machine_count": len(m_set),
                "machines": sorted(list(m_set)),
                "crash_count": len(driver_crashes[drv]),
            })

    # Sắp xếp giảm dần theo số máy bị ảnh hưởng
    flagged_buckets.sort(key=lambda x: x["machine_count"], reverse=True)
    flagged_drivers.sort(key=lambda x: x["machine_count"], reverse=True)

    return {
        "window_days": window_days,
        "min_machines": min_machines,
        "total_crashes_in_window": len(all_crashes),
        "fleet_buckets": flagged_buckets,
        "fleet_drivers": flagged_drivers,
    }


def generate_fleet_evidences_for_crash(
    crash_id: int,
    suspect_driver: str,
    failure_bucket_id: str,
    fleet_summary: Dict[str, Any],
) -> List[Evidence]:
    """
    Sinh các bằng chứng từ phân tích đội máy (Phần 2.3).
    Cộng điểm cho nhóm driver/phần mềm, TUYỆT ĐỐI KHÔNG cộng cho phần cứng.
    """
    evidences: List[Evidence] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Kiểm tra suspect_driver
    clean_drv = (suspect_driver or "").strip().lower()
    if clean_drv:
        for fd in fleet_summary.get("fleet_drivers", []):
            if fd["driver"] == clean_drv:
                k_machines = fd["machine_count"]
                m_names = ", ".join(fd["machines"][:4])
                evidences.append(
                    Evidence(
                        crash_id=crash_id,
                        kind="fleet",
                        source="Fleet Analyzer",
                        time_utc=now_iso,
                        summary=f"Driver '{clean_drv}' cũng gây sập trên {k_machines} máy khác trong đội",
                        detail=f"Mẫu hình sự cố diện rộng: driver {clean_drv} xuất hiện trên các máy {m_names}. Củng cố kết luận lỗi driver/phần mềm, loại trừ phần cứng riêng lẻ.",
                        strength="medium",
                        polarity="support",
                        group_id="fleet_cross_machine",
                    )
                )
                break

    # 2. Kiểm tra failure_bucket_id
    clean_b = (failure_bucket_id or "").strip()
    if clean_b and clean_b.upper() not in ("N/A", "UNKNOWN"):
        for fb in fleet_summary.get("fleet_buckets", []):
            if fb["bucket_id"] == clean_b:
                k_machines = fb["machine_count"]
                m_names = ", ".join(fb["machines"][:4])
                evidences.append(
                    Evidence(
                        crash_id=crash_id,
                        kind="fleet",
                        source="Fleet Analyzer",
                        time_utc=now_iso,
                        summary=f"Bucket lỗi '{clean_b[:30]}...' trùng khớp trên {k_machines} máy khác",
                        detail=f"Mã định danh lỗi (FAILURE_BUCKET_ID) xuất hiện trên các máy: {m_names}.",
                        strength="medium",
                        polarity="support",
                        group_id="fleet_cross_machine",
                    )
                )
                break

    return evidences
