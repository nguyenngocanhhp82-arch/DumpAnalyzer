"""
Bộ đánh giá luật Minidump Triage (Triage Rules Evaluator) (Đợt 05).
Chuyển đổi kết quả TriageResult thành các Bằng chứng (Evidence) định lượng cho Scorer.
Tuân thủ N5 (bằng chứng từ dump triage tối đa mức vừa/weak/info) và N7 (trọng số khởi điểm).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from dumpanalyzer.core.config import get_rules_dir
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.core.models import Evidence
from dumpanalyzer.engine.module_classifier import names_have_class, names_have_class_not

logger = get_logger("triage_evaluator")


def load_triage_rules(rules_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Tải cấu hình luật triage từ config/rules/triage_rules.yaml."""
    r_dir = rules_dir or get_rules_dir()
    triage_file = r_dir / "triage_rules.yaml"
    if not triage_file.exists():
        return {"version": 1, "fs_bugchecks": ["0x23", "0x24"], "rules": []}

    try:
        with open(triage_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"Lỗi nạp triage_rules.yaml: {e}")
        return {"version": 1, "fs_bugchecks": ["0x23", "0x24"], "rules": []}


def evaluate_triage_evidence(
    triage: Any,
    bugcheck_code: str = "",
    crash_id: Optional[int] = None,
    rules_dir: Optional[Path] = None,
) -> List[Evidence]:
    """
    Đánh giá kết quả TriageResult hoặc dictionary theo các quy tắc trong triage_rules.yaml.
    Trả về danh sách Evidence có kind='dump'.
    """
    is_ok = getattr(triage, "ok", None)
    if is_ok is None and isinstance(triage, dict):
        is_ok = triage.get("ok", False)
    if not is_ok:
        return []

    if isinstance(triage, dict):
        hdr = triage.get("header", {}) or {}
        stack_mods = triage.get("stack_modules_in_order", []) or []
        loaded_mods = [m.get("name", "") if isinstance(m, dict) else str(m) for m in (triage.get("modules") or [])]
        unloaded_mods = triage.get("unloaded", []) or []
        exc = triage.get("exception", {}) or {}
    else:
        hdr = getattr(triage, "header", {}) or {}
        stack_mods = getattr(triage, "stack_modules_in_order", []) or []
        loaded_mods = [m.get("name", "") for m in getattr(triage, "modules", []) or []]
        unloaded_mods = getattr(triage, "unloaded", []) or []
        exc = getattr(triage, "exception", {}) or {}

    if not bugcheck_code:
        bugcheck_code = hdr.get("bugcheck_code", "")

    rules_data = load_triage_rules(rules_dir=rules_dir)
    rule_list = rules_data.get("rules", [])
    fs_bugchecks = {str(x).upper() for x in rules_data.get("fs_bugchecks", ["0x23", "0x24"])}

    # Chuẩn hóa mã bugcheck (ví dụ "0x23", "0X23", "0x00000023" -> "0X23")
    bc_clean = bugcheck_code.upper().strip()
    try:
        bc_int = int(bc_clean, 16)
        bc_norm = f"0X{bc_int:X}"
    except ValueError:
        bc_norm = bc_clean

    evidences: List[Evidence] = []

    for rule in rule_list:
        rid = rule.get("id", "")
        when = rule.get("when", {})
        matched = True

        # 1. Điều kiện bugcheck_in
        if "bugcheck_in" in when:
            allowed_bcs_key = when["bugcheck_in"]
            if allowed_bcs_key == "fs_bugchecks":
                if bc_norm not in fs_bugchecks and bc_clean not in fs_bugchecks:
                    matched = False
            elif isinstance(allowed_bcs_key, list):
                allowed_set = {str(x).upper() for x in allowed_bcs_key}
                if bc_norm not in allowed_set and bc_clean not in allowed_set:
                    matched = False

        if not matched:
            continue

        # 2. Điều kiện stack_has_class
        if "stack_has_class" in when:
            cls_target = when["stack_has_class"]
            if not names_have_class(stack_mods, cls_target, rules_dir=rules_dir):
                matched = False

        if not matched:
            continue

        # 3. Điều kiện stack_has_class_not
        if "stack_has_class_not" in when:
            cls_forbidden = when["stack_has_class_not"]
            if not names_have_class_not(stack_mods, cls_forbidden, rules_dir=rules_dir):
                matched = False

        if not matched:
            continue

        # 4. Điều kiện modules_have_class
        if "modules_have_class" in when:
            cls_mod = when["modules_have_class"]
            if not names_have_class(loaded_mods, cls_mod, rules_dir=rules_dir):
                matched = False

        if not matched:
            continue

        # 5. Điều kiện unloaded_has_class
        if "unloaded_has_class" in when:
            cls_unl = when["unloaded_has_class"]
            if not names_have_class(unloaded_mods, cls_unl, rules_dir=rules_dir):
                matched = False

        if not matched:
            continue

        # 6. Điều kiện exception
        if "exception_code" in when:
            expected_code = str(when["exception_code"]).upper()
            actual_code = str(exc.get("code", "")).upper()
            if actual_code != expected_code:
                matched = False

        if not matched:
            continue

        if "exception_access" in when:
            # access = read (info[0] == 0 hoặc meaning chứa ĐỌC)
            meaning = exc.get("meaning", "").upper()
            params = exc.get("parameters", [])
            is_read = ("ĐỌC" in meaning) or (len(params) > 0 and params[0] in ("0x0", "0", 0))
            if when["exception_access"] == "read" and not is_read:
                matched = False

        if not matched:
            continue

        if "exception_address_lt" in when:
            max_addr = when["exception_address_lt"]
            params = exc.get("parameters", [])
            if len(params) >= 2:
                try:
                    p1_val = int(str(params[1]), 16) if isinstance(params[1], str) else int(params[1])
                    if p1_val >= max_addr:
                        matched = False
                except Exception:
                    matched = False
            else:
                matched = False

        if not matched:
            continue

        # Khớp toàn bộ điều kiện! Tạo Evidence
        summary = rule.get("summary", rid)
        strength = rule.get("strength", "medium")
        effect = rule.get("effect", {})

        # Xác định polarity
        polarity = "support"
        if effect.get("reduce"):
            polarity = "refute"
        elif not effect.get("add") and not effect.get("reduce"):
            polarity = "neutral"

        # Chi tiết hiển thị
        detail_lines = []
        if rid == "fs_path_all_microsoft":
            detail_lines.append(f"Thứ tự module trong ngăn xếp: {', '.join(stack_mods[:5])}")
        elif rid == "usb_mass_storage_active":
            usb_active = [m for m in loaded_mods if m.lower() in ("usbstor.sys", "uaspstor.sys")]
            detail_lines.append(f"Driver lưu trữ USB đang nạp: {', '.join(usb_active)}")
        elif rid == "usb_mass_storage_churn":
            usb_unl = [m for m in unloaded_mods if "usbstor" in m.lower() or "uaspstor" in m.lower()]
            detail_lines.append(f"Driver lưu trữ USB đã gỡ: {', '.join(usb_unl)}")
        elif rid == "null_dereference_info":
            if exc.get("meaning"):
                detail_lines.append(exc["meaning"])
            if exc.get("module"):
                detail_lines.append(f"Tại: {exc['module']}+{exc.get('module_offset', '0x0')}")

        ev = Evidence(
            crash_id=crash_id,
            kind="dump",
            source="Minidump Triage",
            summary=summary,
            detail="; ".join(detail_lines) if detail_lines else summary,
            strength=strength,
            polarity=polarity,
            group_id=rid,
            rule_id=rid,
        )
        evidences.append(ev)

    return evidences
