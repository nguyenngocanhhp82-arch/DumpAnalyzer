"""
Module chấm điểm và suy luận nguyên nhân (Rule Engine Scorer).
Hiện thực hóa thuật toán chấm điểm theo Mục 6 của Handoff và các quy tắc trần độ tin cậy trong UPDATE_01.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.engine.rule_loader import normalize_bugcheck_code
from dumpanalyzer.core.timeutil import parse_to_utc

logger = logging.getLogger("dumpanalyzer.engine.scorer")

# Danh sách tên hiển thị thân thiện bằng tiếng Việt cho các nhóm nguyên nhân
SUSPECT_LABELS_VI = {
    "gpu": "Card màn hình / Driver GPU",
    "ram": "Bộ nhớ RAM",
    "storage": "Ổ cứng / SSD / Bộ điều khiển lưu trữ",
    "driver": "Driver bên thứ ba",
    "cpu": "Bộ xử lý CPU / Ép xung",
    "psu": "Bộ nguồn máy tính (PSU) / Nguồn điện",
    "thermal": "Quá nhiệt (Nhiệt độ CPU/GPU)",
    "bios": "BIOS / Bo mạch chủ (Motherboard)",
    "network": "Card mạng LAN / Wi-Fi",
    "update": "Bản cập nhật Windows / Phần mềm mới cài",
    "unknown": "Chưa xác định",
}


def get_suspect_label_vi(suspect: str) -> str:
    """Trả về nhãn hiển thị tiếng Việt cho nhóm nghi ngờ."""
    if suspect.startswith("driver:"):
        drv_name = suspect.split(":", 1)[1]
        return f"Driver {drv_name}"
    return SUSPECT_LABELS_VI.get(suspect, suspect)


def compute_event_points(
    evidences: List[Evidence],
    rules: Dict[str, Any],
    initial_top_suspects: Optional[Set[str]] = None,
) -> Tuple[Dict[str, float], Set[int]]:
    """
    Tính điểm nghi ngờ từ danh sách bằng chứng (Evidences) cho một vụ sập.
    Hỗ trợ:
      - Tra cứu event_rules.yaml cho ev.kind == 'eventlog'
      - Hệ số đồng thuận 1.5x nếu suspect nằm trong initial_top_suspects
      - Giới hạn trần 'cap' cho từng quy tắc và suspect
      - Bằng chứng SMART (ev.kind == 'smart'): +30 điểm cho storage
      - Bằng chứng Update (ev.kind == 'update'): +25 điểm cho update
      - Bằng chứng Sysinfo (ev.kind == 'sysinfo'): theo system_rules.yaml
      - Bằng chứng Thiết bị Asset (ev.kind == 'asset'): hỗ trợ các linh kiện già cỗi
      - Bằng chứng Đội máy Fleet (ev.kind == 'fleet'): +25 driver, +20 software, KHÔNG cộng phần cứng
      - Bằng chứng Kiểm tra phần cứng (ev.kind == 'hwtest'):
          * failed: +35 điểm ủng hộ cho linh kiện
          * passed / refute: trừ điểm nhóm nghi vấn tương ứng (sàn 0.0)
    Trả về:
      - (points_dict, used_evidence_ids)
    """
    points: Dict[str, float] = {}
    used_ids: Set[int] = set()
    event_rules = rules.get("event_rules", [])
    sys_rules = rules.get("system_rules", {})

    # Theo dõi điểm đã cộng dồn cho mỗi (rule_index, suspect) để áp dụng cap
    rule_pts_accumulated: Dict[Tuple[int, str], float] = {}

    for ev in evidences:
        ev_id = ev.id if ev.id is not None else 0
        polarity = getattr(ev, "polarity", "support") or "support"
        strength = getattr(ev, "strength", "weak") or "weak"

        if polarity == "refute":
            # Xử lý bằng chứng phản bác: giảm điểm nhóm tương ứng (sàn 0.0)
            deduct = 30.0 if strength == "strong" else (20.0 if strength == "medium" else 10.0)
            gid = (getattr(ev, "group_id", "") or "").lower()
            ev_desc = f"{ev.source} {ev.summary} {ev.detail}".lower()
            refute_target = ""
            for cand in ["ram", "storage", "gpu", "cpu", "psu", "thermal", "driver"]:
                if cand in gid or f"({cand})" in ev_desc or f" {cand} " in ev_desc or f": {cand}" in ev_desc:
                    refute_target = cand
                    break
            if refute_target:
                current_p = points.get(refute_target, 0.0)
                points[refute_target] = max(0.0, current_p - deduct)
            if ev_id:
                used_ids.add(ev_id)
            continue

        if ev.kind == "eventlog":
            matched = False
            for idx, rule in enumerate(event_rules):
                rule_source = rule.get("source", "").lower()
                if rule_source and rule_source in ev.source.lower():
                    rule_ids = rule.get("ids", [])
                    if ev.event_id in rule_ids or not rule_ids:
                        matched = True
                        rule_cap = rule.get("cap")
                        for susp, weight in rule.get("adds", {}).items():
                            factor = 1.5 if (initial_top_suspects and susp in initial_top_suspects) else 1.0
                            raw_add = float(weight) * factor

                            if rule_cap is not None:
                                current_rule_pts = rule_pts_accumulated.get((idx, susp), 0.0)
                                allowed = max(0.0, float(rule_cap) - current_rule_pts)
                                actual_add = min(raw_add, allowed)
                                rule_pts_accumulated[(idx, susp)] = current_rule_pts + actual_add
                            else:
                                actual_add = raw_add

                            if actual_add > 0:
                                points[susp] = points.get(susp, 0.0) + actual_add

            if matched and ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "smart":
            points["storage"] = points.get("storage", 0.0) + 30.0
            if ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "update":
            points["update"] = points.get("update", 0.0) + 25.0
            if ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "sysinfo":
            gid = getattr(ev, "group_id", "")
            if gid == "sysinfo_disk_wear":
                points["storage"] = points.get("storage", 0.0) + 30.0
            elif gid == "sysinfo_disk_health":
                points["storage"] = points.get("storage", 0.0) + 35.0
            elif gid == "sysinfo_disk_io_errors":
                points["storage"] = points.get("storage", 0.0) + 25.0
            elif gid == "sysinfo_ram_oc":
                points["ram"] = points.get("ram", 0.0) + 15.0
            elif gid == "sysinfo_bios_age":
                points["cpu"] = points.get("cpu", 0.0) + 10.0
                points["ram"] = points.get("ram", 0.0) + 10.0
            elif gid == "sysinfo_gpu_driver_age":
                points["driver"] = points.get("driver", 0.0) + 15.0
                points["gpu"] = points.get("gpu", 0.0) + 10.0
            else:
                for r_cat in sys_rules.values():
                    if isinstance(r_cat, dict) and r_cat.get("group_id") == gid:
                        for s, pts in r_cat.get("adds", {}).items():
                            points[s] = points.get(s, 0.0) + float(pts)
            if ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "asset":
            gid = getattr(ev, "group_id", "")
            if gid == "asset_machine_age":
                points["ram"] = points.get("ram", 0.0) + 10.0
                points["storage"] = points.get("storage", 0.0) + 10.0
                points["cpu"] = points.get("cpu", 0.0) + 10.0
                points["psu"] = points.get("psu", 0.0) + 10.0
            elif gid == "asset_repair_count":
                points["ram"] = points.get("ram", 0.0) + 15.0
                points["storage"] = points.get("storage", 0.0) + 15.0
                points["psu"] = points.get("psu", 0.0) + 15.0
            if ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "fleet":
            # TUYỆT ĐỐI KHÔNG cộng cho phần cứng
            points["driver"] = points.get("driver", 0.0) + 25.0
            points["software"] = points.get("software", 0.0) + 20.0
            if ev_id:
                used_ids.add(ev_id)

        elif ev.kind == "hwtest":
            gid = (getattr(ev, "group_id", "") or "").lower()
            ev_desc = f"{ev.source} {ev.summary} {ev.detail}".lower()
            for cand in ["ram", "storage", "cpu", "gpu"]:
                if cand in gid or cand in ev_desc:
                    points[cand] = points.get(cand, 0.0) + 35.0
            if ev_id:
                used_ids.add(ev_id)

    return points, used_ids



def _enrich_evidences(evidences: List[Evidence], rules: Dict[str, Any]) -> List[Evidence]:
    """Làm giàu thông tin strength, polarity, group_id cho evidence từ cấu hình rules nếu chưa có."""
    event_rules = rules.get("event_rules", [])
    enriched: List[Evidence] = []
    for ev in evidences:
        # Tạo bản sao hoặc giữ nguyên
        pol = getattr(ev, "polarity", "support") or "support"
        st = getattr(ev, "strength", "weak") or "weak"
        gid = getattr(ev, "group_id", "") or ""

        # Nếu là eventlog và chưa có strength đặc thù
        if ev.kind == "eventlog" and (st == "weak" or not gid):
            matched = False
            for r in event_rules:
                r_src = r.get("source", "").lower()
                if r_src and r_src in (ev.source or "").lower():
                    r_ids = r.get("ids", [])
                    if ev.event_id in r_ids or not r_ids:
                        st = r.get("strength", st)
                        pol = r.get("polarity", pol)
                        gid = r.get("group_id", gid)
                        matched = True
                        break
            if not matched and not gid:
                gid = f"eventlog_{ev.source}_{ev.event_id}"

        elif ev.kind == "smart":
            st = "strong"
            gid = gid or "smart_disk"
        elif ev.kind == "update":
            st = "medium"
            gid = gid or "windows_update"
        elif ev.kind == "fleet":
            st = "medium"
            gid = gid or "fleet_cross_machine"
        elif ev.kind == "sysinfo":
            st = st if st != "weak" else "medium"
            gid = gid or "sysinfo"

        enriched_ev = Evidence(
            id=ev.id,
            crash_id=ev.crash_id,
            kind=ev.kind,
            source=ev.source,
            event_id=ev.event_id,
            time_utc=ev.time_utc,
            summary=ev.summary,
            detail=ev.detail,
            strength=st,
            polarity=pol,
            group_id=gid or f"{ev.kind}_{ev.source}",
        )
        enriched.append(enriched_ev)
    return enriched


def evaluate_confidence(
    top_suspect: str,
    top_score: float,
    evidences: List[Evidence],
    is_header_only: bool = False,
    is_log_only: bool = False,
    crash_count: int = 1,
    policy: Optional[Dict[str, Any]] = None,
    bc_code: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Đánh giá độ tin cậy theo Phần 3.2 tách biệt khỏi suspicion_share:
    - 'cao': >= 2 bằng chứng STRONG ủng hộ nhóm đứng đầu từ >= 2 group_id độc lập và 0 phản bác STRONG.
    - 'trung bình': 1 bằng chứng STRONG ủng hộ, HOẶC >= 2 bằng chứng MEDIUM độc lập.
    - 'thấp': các trường hợp còn lại (chỉ có mã bug check, header_only, log_only, hoặc 1 dump đơn lẻ thiếu bằng chứng).
    """
    default_policy = {
        "high_min_strong_evidence": 2,
        "high_max_refute_strong": 0,
        "medium_min_strong": 1,
        "medium_min_medium_groups": 2,
    }
    pol = dict(default_policy)
    if policy:
        pol.update(policy)

    # Xác định các mục tiêu và từ đồng nghĩa liên quan đến top_suspect
    clean_top = top_suspect.lower()
    top_targets = {clean_top, "driver"} if clean_top.startswith("driver:") else {clean_top}

    # Bổ sung từ khóa/từ đồng nghĩa đặc thù theo nhóm
    synonyms_map = {
        "gpu": {"display", "card đồ hoạ", "vga", "graphics", "tdr", "nvlddmkm", "amdkmdag", "igdkmd"},
        "ram": {"memory", "bộ nhớ", "dimm", "ecc", "mdsched", "memtest"},
        "storage": {"disk", "ssd", "hdd", "nvme", "sata", "smart", "ổ cứng", "chkdsk", "stornvme", "storahci"},
        "cpu": {"processor", "vi xử lý", "microcode", "errrec"},
        "psu": {"power", "nguồn", "kernel-power"},
        "thermal": {"nhiệt", "temperature", "quá nhiệt", "overheating"},
        "update": {"cập nhật", "windowsupdate", "hotfix", "kb"},
    }
    if clean_top in synonyms_map:
        top_targets.update(synonyms_map[clean_top])

    strong_support_groups: Set[str] = set()
    medium_support_groups: Set[str] = set()
    strong_refute_count = 0

    for ev in evidences:
        pol_type = getattr(ev, "polarity", "support") or "support"
        strength = getattr(ev, "strength", "weak") or "weak"
        gid = getattr(ev, "group_id", "") or f"{ev.kind}_{ev.source}_{ev.event_id}"

        # Kiểm tra tính liên quan của bằng chứng
        ev_text = f"{ev.source} {ev.summary} {ev.detail} {gid}".lower()
        is_relevant = any(t in ev_text for t in top_targets)
        if not is_relevant and any(k in ev_text for k in ("cdb", "whea", "dump")):
            is_relevant = True

        if pol_type == "refute":
            if is_relevant and strength == "strong":
                strong_refute_count += 1
        else:
            if is_relevant:
                if strength == "strong":
                    strong_support_groups.add(gid)
                elif strength in ("medium", "weak"):
                    medium_support_groups.add(gid)


    # 1. Ràng buộc trần đối với log_only
    if is_log_only:
        norm_bc = normalize_bugcheck_code(bc_code or "")
        if norm_bc in ("0", "0x0", ""):
            return "thấp", "Trần log_only BugcheckCode=0 (mất nguồn/treo): Không có dump, độ tin cậy 'thấp'."
        if len(strong_support_groups) >= 1 or len(medium_support_groups) >= 1:
            return "trung bình", "Trần log_only có event hỗ trợ: Có mã lỗi và sự kiện độc lập củng cố."
        return "thấp", "Trần log_only không có event hỗ trợ: Độ tin cậy 'thấp'."


    # 2. Ràng buộc trần đối với header_only
    if is_header_only:
        if len(strong_support_groups) >= 1 or len(medium_support_groups) >= 1:
            return "trung bình", "Trần header_only: Không có cdb giải mã call stack sâu, tối đa mức 'trung bình'."
        return "thấp", "Trần header_only: Chỉ đọc thông tin tiêu đề dump, độ tin cậy 'thấp'."

    # 3. Phân tích cdb: Chỉ có 1 dump và không có bằng chứng độc lập (chỉ có mã bug check)
    if crash_count == 1 and len(strong_support_groups) == 0 and len(medium_support_groups) == 0:
        return "thấp", "Đánh giá mức THẤP: Chỉ có 1 dump và dữ liệu suy luận chủ yếu từ mã Bug Check."

    # 4. Đánh giá theo chính sách độc lập
    min_strong_req = int(pol.get("high_min_strong_evidence", 2))
    max_refute_req = int(pol.get("high_max_refute_strong", 0))

    if len(strong_support_groups) >= min_strong_req and strong_refute_count <= max_refute_req:
        grps_repr = ", ".join(sorted(list(strong_support_groups)))
        return "cao", f"Đạt mức CAO vì có {len(strong_support_groups)} nhóm bằng chứng mạnh độc lập ({grps_repr}) ủng hộ và không có bằng chứng phản bác mạnh."

    if len(strong_support_groups) >= int(pol.get("medium_min_strong", 1)) or len(medium_support_groups) >= int(pol.get("medium_min_medium_groups", 2)):
        return "trung bình", f"Đạt mức TRUNG BÌNH do có bằng chứng độc lập ({len(strong_support_groups)} nhóm mạnh, {len(medium_support_groups)} nhóm vừa) củng cố."

    return "thấp", "Đánh giá mức THẤP do chưa đủ 2 nguồn bằng chứng mạnh độc lập."



def score_single_crash(
    crash: Crash,
    evidences: List[Evidence],
    rules: Dict[str, Any],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Chấm điểm nguyên nhân cho một vụ sập (Crash) đơn lẻ.
    Trả về dict chứa:
      - 'suspect_scores': danh sách (suspect, score_pct) đã sắp xếp giảm dần
      - 'top_suspect': nhóm nghi ngờ cao nhất
      - 'top_score': điểm % cao nhất (0 - 100) (suspicion_share)
      - 'suspicion_share': tỷ trọng nghi ngờ (%)
      - 'confidence': 'thấp', 'trung bình', 'cao', hoặc 'không đủ dữ kiện'
      - 'confidence_rationale': giải thích vì sao xếp loại độ tin cậy
      - 'used_evidence_ids': danh sách ID các bằng chứng được dùng
      - 'is_log_only': bool
      - 'applied_caps': mô tả trần độ tin cậy đã áp dụng
      - 'notes': ghi chú kỹ thuật
    """
    raw_scores: Dict[str, float] = {}
    used_evidence_ids: List[int] = []
    notes: List[str] = []

    is_log_only = (crash.analyzed_by == "log_only" or crash.dump_type == "none")
    is_header_only = (crash.analyzed_by == "header_only")

    # 1. Điểm khởi đầu từ bugcheck_rules.yaml
    bc_code = normalize_bugcheck_code(crash.bugcheck_code) if crash.bugcheck_code else "0x0"
    bc_rules = rules.get("bugchecks", {})

    rule_for_code = bc_rules.get(bc_code)
    if not rule_for_code and is_log_only and bc_code in ("0", "0x0", ""):
        rule_for_code = bc_rules.get("0x0")

    if rule_for_code:
        for suspect, pts in rule_for_code.get("suspects", {}).items():
            raw_scores[suspect] = raw_scores.get(suspect, 0.0) + float(pts)
    else:
        # Nếu mã lỗi chưa có trong YAML rules: cấp điểm cơ bản
        raw_scores["driver"] = 35.0
        raw_scores["ram"] = 25.0
        raw_scores["storage"] = 20.0
        raw_scores["cpu"] = 20.0

    # Xác định các giả thuyết ban đầu từ dump/mã lỗi để tính đồng thuận sau này
    initial_top_suspects: Set[str] = {
        k for k, v in sorted(raw_scores.items(), key=lambda item: item[1], reverse=True)[:2]
    }

    # 2. Phân tích Driver / Module gây lỗi
    driver_map = rules.get("drivers", {})
    ms_core_modules = rules.get("ms_core_modules", [])

    img = (crash.image_name or "").strip().lower()
    mod = (crash.module_name or "").strip().lower()
    active_module = img if img else mod

    # Trích xuất suspect driver nếu cdb parser đã phát hiện trong call stack (ưu tiên crash.suspect_driver)
    suspect_driver_in_stack = ""
    if getattr(crash, "suspect_driver", ""):
        suspect_driver_in_stack = crash.suspect_driver.strip().lower()
    elif crash.cdb_raw_output and "Driver nghi vấn trong stack:" in crash.cdb_raw_output:
        for line in crash.cdb_raw_output.splitlines():
            if "Driver nghi vấn trong stack:" in line:
                suspect_driver_in_stack = line.split(":", 1)[1].strip().lower()
                break

    if is_log_only:
        # Crash không có dump TUYỆT ĐỐI không kết luận driver cụ thể
        pass
    else:
        # Có dump: phân định Nạn nhân vs Thủ phạm
        is_ms_module = any(active_module.endswith(ms_mod) for ms_mod in ms_core_modules)

        if is_ms_module:
            notes.append(f"Module sập là '{active_module}' (Microsoft OS Core) - đây là nạn nhân.")
            if suspect_driver_in_stack:
                notes.append(f"Phát hiện driver bên thứ ba trong stack: '{suspect_driver_in_stack}'.")
                drv_info = driver_map.get(suspect_driver_in_stack)
                if drv_info:
                    dev_type = drv_info.get("type", "driver")
                    raw_scores[dev_type] = raw_scores.get(dev_type, 0.0) + 50.0
                    initial_top_suspects.add(dev_type)
                else:
                    raw_scores[f"driver:{suspect_driver_in_stack}"] = (
                        raw_scores.get(f"driver:{suspect_driver_in_stack}", 0.0) + 40.0
                    )
                    initial_top_suspects.add(f"driver:{suspect_driver_in_stack}")
            else:
                if bc_code in ("0x1A", "0x50", "0x4E"):
                    raw_scores["ram"] = raw_scores.get("ram", 0.0) + 20.0
                elif bc_code in ("0x124", "0x101"):
                    raw_scores["cpu"] = raw_scores.get("cpu", 0.0) + 20.0
                elif bc_code in ("0x7B", "0x7A", "0x24"):
                    raw_scores["storage"] = raw_scores.get("storage", 0.0) + 20.0
        elif active_module:
            drv_info = driver_map.get(active_module)
            if drv_info:
                dev_type = drv_info.get("type", "driver")
                raw_scores[dev_type] = raw_scores.get(dev_type, 0.0) + 60.0
                initial_top_suspects.add(dev_type)
            else:
                raw_scores[f"driver:{active_module}"] = raw_scores.get(f"driver:{active_module}", 0.0) + 50.0
                initial_top_suspects.add(f"driver:{active_module}")

    # 3. Cộng điểm từ Event Log / Sysinfo / HwTest
    ev_points, ev_used_ids = compute_event_points(evidences, rules, initial_top_suspects)
    for susp, pts in ev_points.items():
        if pts > 0:
            raw_scores[susp] = raw_scores.get(susp, 0.0) + pts

    used_evidence_ids.extend(ev_used_ids)

    # 4. Chuẩn hoá điểm về thang 0 - 100 (suspicion_share)
    total_raw = sum(raw_scores.values())
    scored_list: List[Tuple[str, float]] = []

    if total_raw > 0:
        for susp, pts in raw_scores.items():
            pct = round((pts / total_raw) * 100.0, 1)
            scored_list.append((susp, pct))
    else:
        scored_list = [("unknown", 0.0)]

    scored_list.sort(key=lambda x: x[1], reverse=True)
    top_suspect, top_score = scored_list[0] if scored_list else ("unknown", 0.0)

    # 5. Đánh giá độ tin cậy tách rời theo Phần 3.2
    conf_policy = settings.get("confidence_policy")
    eval_evs = _enrich_evidences(evidences, rules)
    if not is_log_only and not is_header_only and crash.analyzed_by == "cdb":
        suspect_drv = active_module if (active_module and not any(active_module.endswith(ms) for ms in ms_core_modules)) else suspect_driver_in_stack
        if suspect_drv:
            eval_evs.append(
                Evidence(
                    kind="dump",
                    source="cdb",
                    summary=f"CDB stack trace phát hiện driver nghi vấn '{suspect_drv}'",
                    strength="strong",
                    polarity="support",
                    group_id=f"cdb_stack_{suspect_drv}",
                )
            )

    confidence, confidence_rationale = evaluate_confidence(
        top_suspect=top_suspect,
        top_score=top_score,
        evidences=eval_evs,
        is_header_only=is_header_only,
        is_log_only=is_log_only,
        crash_count=1,
        policy=conf_policy,
        bc_code=bc_code,
    )


    applied_caps = ""
    if is_log_only:
        applied_caps = f"Trần log_only: {confidence_rationale}"
    elif is_header_only:
        applied_caps = f"Trần header_only: {confidence_rationale}"
    elif confidence == "trung bình":
        applied_caps = f"Trần 1 crash: {confidence_rationale}"
    elif confidence != "cao":
        applied_caps = confidence_rationale

    return {
        "suspect_scores": scored_list,
        "top_suspect": top_suspect,
        "top_score": top_score,
        "suspicion_share": top_score,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "used_evidence_ids": list(set(used_evidence_ids)),
        "is_log_only": is_log_only,
        "applied_caps": applied_caps,
        "notes": notes,
    }




def score_machine_crashes(
    crashes_with_evidences: List[Tuple[Crash, List[Evidence]]],
    rules: Dict[str, Any],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Chấm điểm và phân tích xu hướng cho toàn bộ máy tính (nhiều vụ sập).
    Tổng hợp điểm các crash, áp dụng patterns.yaml, thưởng lặp lại và phát hiện mâu thuẫn.
    """
    if not crashes_with_evidences:
        return {
            "suspect_scores": [("unknown", 0.0)],
            "top_suspect": "unknown",
            "top_score": 0.0,
            "confidence": "không đủ dữ kiện",
            "used_evidence_ids": [],
            "is_conflicted": False,
            "conflict_note": "",
            "patterns_matched": [],
            "crash_count": 0,
        }

    normalized_crashes: List[Tuple[Crash, List[Evidence]]] = [
        item if isinstance(item, tuple) else (item, [])
        for item in crashes_with_evidences
    ]

    # Nếu chỉ có 1 crash: kế thừa trực tiếp kết quả crash đơn lẻ
    if len(normalized_crashes) == 1:
        crash, evs = normalized_crashes[0]
        res = score_single_crash(crash, evs, rules, settings)
        res["is_conflicted"] = False
        res["conflict_note"] = ""
        res["patterns_matched"] = []
        res["crash_count"] = 1
        return res

    # Có từ 2 crash trở lên: Tổng hợp điểm
    aggregated_scores: Dict[str, float] = {}
    all_evidence_ids: Set[int] = set()
    top_suspect_per_crash: List[str] = []
    dump_hypotheses: List[str] = []
    log_hypotheses: List[str] = []

    log_only_weight = float(settings.get("log_only_weight", 0.5))
    repeat_multiplier = float(settings.get("repeat_multiplier", 1.25))
    conflict_threshold = float(settings.get("conflict_threshold", 15))

    ms_core_modules = rules.get("ms_core_modules", [])

    for crash, evs in normalized_crashes:
        c_res = score_single_crash(crash, evs, rules, settings)
        c_weight = log_only_weight if c_res["is_log_only"] else 1.0

        for susp, pct in c_res["suspect_scores"]:
            aggregated_scores[susp] = aggregated_scores.get(susp, 0.0) + (pct * c_weight)

        all_evidence_ids.update(c_res["used_evidence_ids"])
        top_suspect_per_crash.append(c_res["top_suspect"])

        # Xác định giả thuyết nghiêng về Dump vs Event Log
        if not c_res["is_log_only"]:
            dump_hypotheses.append(c_res["top_suspect"])

        # Tìm giả thuyết từ các sự kiện Event Log của crash này
        log_pts_crash, _ = compute_event_points(evs, rules, initial_top_suspects=None)
        if log_pts_crash:
            top_log_crash = max(log_pts_crash, key=log_pts_crash.get)
            log_hypotheses.append(top_log_crash)
        elif c_res["is_log_only"]:
            log_hypotheses.append(c_res["top_suspect"])

    # Áp dụng patterns.yaml
    patterns = rules.get("patterns", [])
    patterns_matched: List[str] = []
    total_crashes = len(crashes_with_evidences)
    driver_map = rules.get("drivers", {})

    # Thu thập crash có module (từ CDB / minidump)
    crashes_with_module: List[Tuple[Crash, str]] = []
    for c, _ in normalized_crashes:
        mod_name = (c.image_name or c.module_name or "").strip().lower()
        if mod_name:
            crashes_with_module.append((c, mod_name))

    for pat in patterns:
        cond = pat.get("when", {})
        pat_name = pat.get("name", "")
        matched = False
        repeating_driver = None

        # Pattern 1: Module khác nhau mỗi lần, toàn module Microsoft
        if cond.get("only_microsoft_modules"):
            min_dumps = cond.get("min_dumps", 3)
            distinct_min = cond.get("distinct_modules_min", 3)
            if len(crashes_with_module) >= min_dumps:
                all_ms = all(
                    any(mod.endswith(ms_mod.lower()) for ms_mod in ms_core_modules)
                    for _, mod in crashes_with_module
                )
                distinct_mods = set(mod for _, mod in crashes_with_module)
                if all_ms and len(distinct_mods) >= distinct_min:
                    matched = True

        # Pattern 2: Cùng một driver bên thứ ba lặp lại
        if cond.get("same_third_party_module_min"):
            min_dumps = cond.get("min_dumps", 3)
            same_min = cond.get("same_third_party_module_min", 3)
            third_party_modules = []
            for _, mod in crashes_with_module:
                is_ms = any(mod.endswith(ms_mod.lower()) for ms_mod in ms_core_modules)
                if not is_ms:
                    third_party_modules.append(mod)

            if len(crashes_with_module) >= min_dumps and third_party_modules:
                from collections import Counter
                counts = Counter(third_party_modules)
                for drv, cnt in counts.items():
                    if cnt >= same_min:
                        repeating_driver = drv
                        matched = True
                        break

        # Pattern 3: Sự cố liên quan cập nhật
        days_after_update = cond.get("first_crash_within_days_after_update")
        if days_after_update is not None:
            crash_dts = []
            for c, _ in normalized_crashes:
                if c.crash_time_utc:
                    dt = parse_to_utc(c.crash_time_utc)
                    if dt:
                        crash_dts.append(dt)
            update_dts = []
            for _, evs in normalized_crashes:
                for ev in evs:
                    if ev.kind == "update" or "windowsupdate" in ev.source.lower():
                        if ev.time_utc:
                            u_dt = parse_to_utc(ev.time_utc)
                            if u_dt:
                                update_dts.append(u_dt)
            if crash_dts and update_dts:
                first_crash_dt = min(crash_dts)
                for u_dt in update_dts:
                    diff_seconds = (first_crash_dt - u_dt).total_seconds()
                    if 0 < diff_seconds <= float(days_after_update) * 86400:
                        matched = True
                        break

        # Pattern 4: Mất nguồn đột ngột không dump (KP41 = 0)
        req_no_dump = cond.get("no_dump", False)
        req_kp41_zero = cond.get("kernelpower41_bugcheck0", False)
        if req_no_dump and req_kp41_zero:
            has_matching_crash = any(
                (c.dump_type in ("none", "") or c.analyzed_by == "log_only" or not c.dump_path)
                and (normalize_bugcheck_code(c.bugcheck_code) in ("0", "0x0", ""))
                for c, _ in normalized_crashes
            )
            if has_matching_crash:
                matched = True
        elif req_kp41_zero:
            if any(normalize_bugcheck_code(c.bugcheck_code) in ("0", "0x0", "") for c, _ in normalized_crashes):
                matched = True
        elif req_no_dump:
            if any((c.dump_type in ("none", "") or c.analyzed_by == "log_only" or not c.dump_path) for c, _ in normalized_crashes):
                matched = True

        if matched:
            patterns_matched.append(pat_name)
            for s, add_pts in pat.get("add", {}).items():
                if s == "driver_of_module":
                    if repeating_driver:
                        drv_info = driver_map.get(repeating_driver)
                        if drv_info:
                            target_s = drv_info.get("type", "driver")
                        else:
                            target_s = f"driver:{repeating_driver}"
                    else:
                        target_s = "driver"
                else:
                    target_s = s
                aggregated_scores[target_s] = aggregated_scores.get(target_s, 0.0) + float(add_pts)

    # Thưởng lặp lại (Repeat Bonus): Cùng một giả thuyết đứng đầu ở >= 3 crash
    from collections import Counter
    suspect_counts = Counter(top_suspect_per_crash)
    for susp, cnt in suspect_counts.items():
        if cnt >= 3 and susp in aggregated_scores:
            aggregated_scores[susp] *= repeat_multiplier

    # Chuẩn hoá điểm tổng hợp về 0 - 100%
    total_agg = sum(aggregated_scores.values())
    final_scored: List[Tuple[str, float]] = []
    if total_agg > 0:
        for s, pts in aggregated_scores.items():
            pct = round((pts / total_agg) * 100.0, 1)
            final_scored.append((s, pct))
    else:
        final_scored = [("unknown", 0.0)]

    final_scored.sort(key=lambda x: x[1], reverse=True)
    top_suspect, top_score = final_scored[0] if final_scored else ("unknown", 0.0)

    # Phát hiện mâu thuẫn (Conflict Detection)
    is_conflicted = False
    conflict_note = ""
    if dump_hypotheses and log_hypotheses:
        top_dump_hypo = Counter(dump_hypotheses).most_common(1)[0][0]
        top_log_hypo = Counter(log_hypotheses).most_common(1)[0][0]

        if top_dump_hypo != top_log_hypo:
            # Lấy điểm của 2 giả thuyết này
            score_dict = dict(final_scored)
            diff = abs(score_dict.get(top_dump_hypo, 0.0) - score_dict.get(top_log_hypo, 0.0))
            if diff < conflict_threshold:
                is_conflicted = True
                conflict_note = (
                    f"Cảnh báo: Dữ liệu chưa thống nhất! "
                    f"Phân tích Dump nghiêng về '{get_suspect_label_vi(top_dump_hypo)}', "
                    f"trong khi Event Log nghiêng về '{get_suspect_label_vi(top_log_hypo)}' "
                    f"(chênh lệch {diff:.1f} điểm < {conflict_threshold} điểm)."
                )

    # Xác định độ tin cậy của máy tách rời khỏi điểm tỷ trọng
    conf_policy = settings.get("confidence_policy")
    all_evidences_list: List[Evidence] = _enrich_evidences(
        [ev for _, evs in normalized_crashes for ev in evs], rules
    )
    for c, _ in normalized_crashes:
        if c.analyzed_by == "cdb":
            img_c = (c.image_name or c.module_name or getattr(c, "suspect_driver", "") or "").strip().lower()
            if img_c and not any(img_c.endswith(ms) for ms in ms_core_modules):
                all_evidences_list.append(
                    Evidence(
                        kind="dump",
                        source="cdb",
                        summary=f"CDB stack trace phát hiện driver nghi vấn trên crash #{c.id}",
                        strength="strong",
                        polarity="support",
                        group_id=f"cdb_dump_{c.id}",
                    )
                )

    # Thêm bằng chứng từ các mẫu hình pattern matched
    for pat in rules.get("patterns", []):
        p_name = pat.get("name", "")
        if p_name in patterns_matched:
            all_evidences_list.append(
                Evidence(
                    kind="pattern",
                    source="patterns",
                    summary=f"Mẫu hình: {p_name}",
                    strength=pat.get("strength", "medium"),
                    polarity="support",
                    group_id=pat.get("group_id", f"pattern_{p_name}"),
                )
            )

    all_is_log_only = all(c.dump_type in ("none", "") or c.analyzed_by == "log_only" for c, _ in normalized_crashes)
    all_is_header_only = all(c.analyzed_by == "header_only" for c, _ in normalized_crashes)

    confidence, confidence_rationale = evaluate_confidence(
        top_suspect=top_suspect,
        top_score=top_score,
        evidences=all_evidences_list,
        is_header_only=all_is_header_only,
        is_log_only=all_is_log_only,
        crash_count=total_crashes,
        policy=conf_policy,
    )


    if is_conflicted and confidence == "cao":
        confidence = "trung bình"
        confidence_rationale += " [Hạ xuống 'trung bình' do phát hiện mâu thuẫn giữa Dump và Event Log]"

    return {
        "suspect_scores": final_scored,
        "top_suspect": top_suspect,
        "top_score": top_score,
        "suspicion_share": top_score,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "used_evidence_ids": list(all_evidence_ids),
        "is_conflicted": is_conflicted,
        "conflict_note": conflict_note,
        "patterns_matched": patterns_matched,
        "crash_count": total_crashes,
    }

