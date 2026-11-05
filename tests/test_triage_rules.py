"""Kiểm thử luật bằng chứng triage và tính điểm (engine/triage_evaluator.py & scorer.py)."""

from dumpanalyzer.engine.triage_evaluator import evaluate_triage_evidence
from dumpanalyzer.engine.scorer import score_single_crash, get_suspect_label_vi
from dumpanalyzer.core.models import Crash, Evidence


def test_triage_evidence_fs_path_all_microsoft():
    """Kiểm tra kích hoạt luật fs_path_all_microsoft khi call stack toàn Microsoft."""
    triage_data = {
        "ok": True,
        "header": {"bugcheck_code": "0x00000023"},
        "stack_modules_in_order": ["FLTMGR.SYS", "fastfat.SYS", "ntoskrnl.exe"],
        "modules": [{"name": "fastfat.SYS"}, {"name": "ntoskrnl.exe"}],
        "unloaded": [],
    }

    evs = evaluate_triage_evidence(triage_data, crash_id=1)
    rule_ids = [e.rule_id for e in evs]
    assert "fs_path_all_microsoft" in rule_ids

    # Kiểm tra polarity phản bác (refute) cho driver bên ngoài
    fs_ev = next(e for e in evs if e.rule_id == "fs_path_all_microsoft")
    assert fs_ev.polarity == "refute"
    assert fs_ev.kind == "dump"


def test_triage_evidence_usb_mass_storage_churn():
    """Kiểm tra kích hoạt luật usb_mass_storage_churn khi USBSTOR.SYS bị gỡ trước crash."""
    triage_data = {
        "ok": True,
        "header": {"bugcheck_code": "0x00000023"},
        "stack_modules_in_order": ["fastfat.SYS", "ntoskrnl.exe"],
        "modules": [{"name": "fastfat.SYS"}],
        "unloaded": ["USBSTOR.SYS", "dump_diskdump.sys"],
    }

    evs = evaluate_triage_evidence(triage_data, crash_id=1)
    rule_ids = [e.rule_id for e in evs]
    assert "usb_mass_storage_churn" in rule_ids

    churn_ev = next(e for e in evs if e.rule_id == "usb_mass_storage_churn")
    assert churn_ev.polarity == "support"
    assert churn_ev.kind == "dump"


def test_score_single_crash_with_triage_evidence():
    """Kiểm tra tính điểm crash 0x23 với bằng chứng triage: storage và usb_peripheral chiếm ưu thế."""
    from dumpanalyzer.engine.rule_loader import load_all_rules
    from dumpanalyzer.core.config import load_settings

    rules = load_all_rules()
    settings = load_settings()

    c = Crash(
        id=1,
        bugcheck_code="0x00000023",
        bugcheck_name="FAT_FILE_SYSTEM",
        image_name="fastfat.SYS",
        module_name="fastfat.SYS",
    )

    ev1 = Evidence(
        crash_id=1,
        kind="dump",
        source="Minidump Triage",
        rule_id="fs_path_all_microsoft",
        group_id="fs_path_all_microsoft",
        polarity="refute",
        strength="medium",
        summary="Toàn bộ chuỗi xử lý là driver chuẩn của Microsoft.",
    )

    ev2 = Evidence(
        crash_id=1,
        kind="dump",
        source="Minidump Triage",
        rule_id="usb_mass_storage_churn",
        group_id="usb_mass_storage_churn",
        polarity="support",
        strength="medium",
        summary="Phát hiện USBSTOR.SYS bị gỡ.",
    )

    scores = score_single_crash(c, [ev1, ev2], rules, settings)
    suspects = [s[0] for s in scores.get("suspect_scores", [])]
    assert "storage" in suspects
    assert "usb_peripheral" in suspects
    assert scores.get("top_suspect") == "storage"
    # fastfat.SYS là Microsoft inbox nên không bị gán nhãn driver:fastfat.SYS làm thủ phạm duy nhất
    assert not any(k.startswith("driver:fastfat.sys") for k in suspects)


def test_suspect_labels_vi_new_groups():
    """Kiểm tra nhãn tiếng Việt cho nhóm storage và usb_peripheral."""
    lbl_storage = get_suspect_label_vi("storage")
    lbl_usb = get_suspect_label_vi("usb_peripheral")
    assert "USB" in lbl_storage or "lưu trữ" in lbl_storage
    assert "USB" in lbl_usb
