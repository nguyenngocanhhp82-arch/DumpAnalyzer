"""
Giao diện dòng lệnh (CLI) của DumpAnalyzer.
Cung cấp các công cụ kiểm tra môi trường, quét dump và kích hoạt phân tích không cần GUI.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from dumpanalyzer import __version__
from dumpanalyzer.core.config import (
    check_environment_summary,
    get_project_root,
    load_settings,
)
from dumpanalyzer.core.logging_setup import setup_logging


from dumpanalyzer.collectors.dump_finder import find_dumps, copy_dump_safely, calculate_sha256
from dumpanalyzer.analyzer.header_parser import parse_dump_header
from dumpanalyzer.storage.db import Database
from dumpanalyzer.core.models import Crash
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.collectors.dump_config import (
    read_registry_crash_control,
    check_pagefile_status,
    check_disk_space_and_ram,
    check_volmgr_events,
    evaluate_readiness,
    apply_automatic_dump,
    CRASH_DUMP_MODES,
    collect_dump_readiness,
    enable_crash_dump,
    rollback_crash_dump,
    STATUS_READY,
    STATUS_READY_PENDING_REBOOT,
    STATUS_ATTENTION,
    STATUS_BLOCKED,
    STATUS_UNKNOWN,
)
from dumpanalyzer.engine.deployment_package import (
    generate_deployment_package,
    aggregate_fleet_reports,
    export_fleet_readiness_excel,
)
from dumpanalyzer.analyzer.cdb_runner import (
    analyze_dump_file,
    warmup_symbols,
)
from dumpanalyzer.engine.correlator import Correlator
from dumpanalyzer.core.models import Evidence, Finding
from dumpanalyzer.engine.rule_loader import validate_rules_and_settings, load_all_rules
from dumpanalyzer.engine.scorer import score_single_crash, score_machine_crashes, get_suspect_label_vi
from dumpanalyzer.engine.verdict import generate_crash_finding, generate_machine_finding





def print_banner():
    banner = f"""
======================================================================
  DumpAnalyzer v{__version__} - Chẩn đoán Dump BSOD & Windows Event Log
  Dành cho Kỹ thuật viên & Quản trị hệ thống IT
======================================================================
"""
    print(banner.strip())


def cmd_scan(args):
    """Quét tìm file dump, đọc header mã lỗi, kiểm tra cache SHA256 và lưu vào SQLite."""
    print_banner()
    settings = load_settings()

    # Xác định đường dẫn quét
    if args.path:
        search_paths = [args.path]
    else:
        search_paths = settings.get("dump_search_paths", [])

    working_dir = Path(settings.get("working_dir", "./workspace"))
    working_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] Đang quét tìm file dump tại: {', '.join(search_paths)}")
    if args.from_date or args.to_date:
        print(f"    Khoảng thời gian: Từ {args.from_date or 'đầu'} đến {args.to_date or 'nay'}")

    dumps = find_dumps(search_paths, from_date=args.from_date, to_date=args.to_date)

    if not dumps:
        print("\n[!] Không tìm thấy file dump nào trong phạm vi đã chọn.")
        return 0

    print(f"[OK] Tìm thấy {len(dumps)} file dump. Đang tiến hành đọc header...\n")

    db = Database()
    results = []

    for item in dumps:
        src_path = item["path"]
        try:
            sha256_hash = calculate_sha256(src_path)
        except Exception as e:
            print(f"[Cảnh báo] Không thể đọc mã hash file {src_path}: {e}")
            continue

        # 1. Kiểm tra cache trong DB
        cached_crash = db.get_crash_by_sha256(sha256_hash)
        if cached_crash and not args.force:
            results.append({
                "time_str": utc_to_local_str(cached_crash["crash_time_utc"]),
                "bugcheck_code": cached_crash["bugcheck_code"] or "N/A",
                "bugcheck_name": cached_crash["bugcheck_name"] or "Không rõ",
                "dump_type": cached_crash["dump_type"] or "mini",
                "status": "[CACHE]",
                "path": str(src_path),
            })
            continue

        # 2. Copy an toàn sang workspace
        try:
            copied_path = copy_dump_safely(src_path, working_dir, file_sha256=sha256_hash)
        except Exception as e:
            print(f"[Cảnh báo] Không thể sao chép {src_path.name}: {e}")
            copied_path = src_path

        # 3. Đọc header
        header_info = parse_dump_header(copied_path)

        # 4. Lưu vào SQLite
        crash_record = Crash(
            dump_path=str(copied_path),
            dump_sha256=sha256_hash,
            dump_type=header_info.dump_type,
            crash_time_utc=header_info.crash_time_utc,
            bugcheck_code=header_info.bugcheck_code,
            bugcheck_name=header_info.bugcheck_name,
            p1=header_info.p1,
            p2=header_info.p2,
            p3=header_info.p3,
            p4=header_info.p4,
            analyzed_by="header_only",
        )

        try:
            if not cached_crash:
                db.insert_crash(crash_record)
        except Exception as e:
            print(f"[Cảnh báo] Lỗi lưu vào CSDL: {e}")

        status_tag = "[MỚI]" if not cached_crash else "[CẬP NHẬT]"
        results.append({
            "time_str": utc_to_local_str(header_info.crash_time_utc),
            "bugcheck_code": header_info.bugcheck_code or "N/A",
            "bugcheck_name": header_info.bugcheck_name or "Chưa rõ",
            "dump_type": header_info.dump_type,
            "status": status_tag,
            "path": str(src_path),
        })

    db.close()

    # In bảng kết quả
    col_time = 20
    col_code = 12
    col_name = 32
    col_type = 8
    col_status = 9

    header_line = (
        f"{'Thời điểm (Giờ địa phương)':<{col_time}} | "
        f"{'Mã lỗi':<{col_code}} | "
        f"{'Tên lỗi BugCheck':<{col_name}} | "
        f"{'Loại':<{col_type}} | "
        f"{'Trạng thái':<{col_status}} | "
        f"Đường dẫn file"
    )
    separator = "-" * len(header_line) + "-" * 20

    print(separator)
    print(header_line)
    print(separator)

    for r in results:
        t_str = r["time_str"][:col_time]
        c_str = r["bugcheck_code"][:col_code]
        n_str = r["bugcheck_name"][:col_name]
        tp_str = r["dump_type"][:col_type]
        st_str = r["status"][:col_status]
        p_str = r["path"]
        print(f"{t_str:<{col_time}} | {c_str:<{col_code}} | {n_str:<{col_name}} | {tp_str:<{col_type}} | {st_str:<{col_status}} | {p_str}")

    print(separator)
    print(f"Tổng số: {len(results)} file dump được hiển thị.\n")
    return 0


def cmd_check_env(args):
    """Thực hiện kiểm tra toàn diện môi trường chạy của hệ thống."""
    print_banner()
    print("\n--- ĐANG KIỂM TRA MÔI TRƯỜNG HỆ THỐNG ---")

    env = check_environment_summary()

    # 1. Hệ điều hành & Python
    print("\n[1] Môi trường thực thi:")
    print(f"    - Nền tảng HĐH:     {env['os_platform']}")
    print(f"    - Phiên bản Python: {env['python_version']}")

    # 2. Quyền Administrator
    print("\n[2] Quyền thực thi:")
    if env["is_admin"]:
        print("    [OK] Đang chạy với quyền Administrator (hoặc root).")
    else:
        print("    [!] Chưa có quyền Administrator.")
        if env["os_platform"] == "win32":
            print("        -> LƯU Ý: Một số file tại 'C:\\Windows\\Minidump' và 'MEMORY.DMP'")
            print("           yêu cầu quyền Admin để đọc. Hãy mở Terminal bằng 'Run as administrator'.")

    # 3. Công cụ cdb.exe (Windows Debugging Tools)
    print("\n[3] Công cụ gỡ lỗi Windows (cdb.exe):")
    if env["cdb_found"]:
        print(f"    [OK] Đã phát hiện cdb.exe tại: {env['cdb_path']}")
    else:
        print("    [X] KHÔNG tìm thấy cdb.exe trên hệ thống!")
        print(env["cdb_guide"])

    # 4. Thư mục dump mặc định
    print("\n[4] Kiểm tra thư mục / file Dump hệ thống:")
    for path_str, exists in env["dump_paths"].items():
        status = "[TỒN TẠI]" if exists else "[KHÔNG THẤY]"
        print(f"    - {path_str:<35} : {status}")

    # 5. Kiểm tra cơ sở dữ liệu mã Bug Check
    json_path = get_project_root() / "config" / "data" / "bugcheck_codes.json"
    print("\n[5] Cơ sở dữ liệu mã Bug Check:")
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"    [OK] Đã nạp thành công {len(data)} mã Bug Check từ file cấu hình.")
        except Exception as e:
            print(f"    [X] Lỗi đọc file bugcheck_codes.json: {e}")
    else:
        print(f"    [X] Chưa tìm thấy file dữ liệu tại {json_path}")

    # 6. Thư mục làm việc
    print("\n[6] Thư mục làm việc tạm (workspace):")
    ws_path = Path(env["working_dir"])
    if not ws_path.is_absolute():
        ws_path = get_project_root() / ws_path
    ws_path.mkdir(parents=True, exist_ok=True)
    print(f"    - Đường dẫn: {ws_path} (Sẵn sàng)")

    print("\n======================================================================")
    print("Kiểm tra hoàn tất. Bạn có thể tiến hành các thao tác tiếp theo.")
    print("======================================================================\n")
    return 0


def cmd_check_dump_config(args):
    """Kiểm tra toàn diện khả năng sinh dump của hệ thống và tuỳ chọn bật CrashDumpEnabled = 7."""
    print_banner()
    print("\n--- KIỂM TRA KHẢ NĂNG GHI DUMP HỆ THỐNG (Crash Readiness) ---")

    reg_data = read_registry_crash_control()
    pf_data = check_pagefile_status()
    disk_data = check_disk_space_and_ram()
    volmgr_data = check_volmgr_events()

    eval_result = evaluate_readiness(reg_data, pf_data, disk_data, volmgr_data)

    # 1. Cấu hình Registry CrashControl
    print("\n[1] Cấu hình Registry (CrashControl):")
    dump_code = reg_data.get("CrashDumpEnabled")
    mode_desc = CRASH_DUMP_MODES.get(dump_code, f"Mã không xác định ({dump_code})")
    print(f"    - CrashDumpEnabled:  {dump_code} ({mode_desc})")
    print(f"    - AutoReboot:        {reg_data.get('AutoReboot')} (Tự khởi động lại sau BSOD)")
    print(f"    - Overwrite:         {reg_data.get('Overwrite')} (Ghi đè file dump cũ)")
    print(f"    - MinidumpDir:       {reg_data.get('MinidumpDir')}")
    print(f"    - DumpFile:          {reg_data.get('DumpFile')}")

    # 2. Tình trạng Pagefile
    print("\n[2] Tình trạng Bộ nhớ ảo (Pagefile):")
    if pf_data["has_system_drive_pagefile"]:
        print("    [OK] Đã phát hiện Pagefile trên ổ đĩa hệ thống.")
    else:
        print("    [!] CẢNH BÁO: Không có Pagefile trên ổ hệ thống (C:).")
    if pf_data.get("details"):
        for d in pf_data["details"]:
            print(f"         + {d}")

    # 3. Dung lượng trống ổ cứng và RAM
    print("\n[3] Dung lượng ổ đĩa & Bộ nhớ RAM:")
    print(f"    - Dung lượng RAM:    {disk_data['ram_gb']} GB")
    print(f"    - Dung lượng trống:  {disk_data['free_disk_gb']} GB trên ổ {disk_data['system_drive']}")
    print(f"    - Mức khuyến nghị:   >= {disk_data['recommended_free_gb']} GB (RAM + 5GB)")
    if disk_data["sufficient_space"]:
        print("    [OK] Đủ dung lượng trống để lưu Kernel / Automatic dump.")
    else:
        print("    [!] CẢNH BÁO: Dung lượng trống thấp hơn mức an toàn để ghi dump.")

    # 4. Lịch sử dịch vụ volmgr
    print("\n[4] Lịch sử dịch vụ ghi dump (volmgr):")
    if volmgr_data["has_failure_161"]:
        print(f"    [!] CẢNH BÁO: Đã từng có sự kiện tạo dump thất bại (Event 161 lúc {volmgr_data['last_failure_time']}).")
    else:
        print("    [OK] Không phát hiện lỗi tạo dump thất bại (Event 161) gần đây.")

    # 5. ĐÁNH GIÁ TỔNG THỂ
    status_tag = f"=== TRẠNG THÁI: [{eval_result['status']}] ==="
    print(f"\n{'=' * len(status_tag)}")
    print(status_tag)
    print(f"{'=' * len(status_tag)}")
    print(f">> {eval_result['summary']}")

    if eval_result["reasons"]:
        print("\nCác vấn đề phát hiện:")
        for r in eval_result["reasons"]:
            print(f"  * {r}")

    if eval_result["recommendations"]:
        print("\nKhuyến nghị hành động:")
        for rec in eval_result["recommendations"]:
            print(f"  -> {rec}")

    print("\n----------------------------------------------------------------------")

    # 6. Xử lý cờ --apply
    if args.apply:
        print("\n[!] BẠN ĐANG YÊU CẦU CẤU HÌNH BẬT GHI DUMP TỰ ĐỘNG (--apply)")
        print("    Chương trình sẽ:")
        print("    1. Sao lưu cấu hình Registry hiện tại ra file .reg trong thư mục 'backup/'.")
        print("    2. Đặt giá trị 'CrashDumpEnabled' thành 7 (Automatic memory dump).")
        print("    3. TUYỆT ĐỐI KHÔNG sửa pagefile và KHÔNG tự khởi động lại máy.\n")

        confirm = input("Bạn có chắc chắn muốn thực hiện thay đổi này? (gõ 'y' để xác nhận): ").strip().lower()
        if confirm == "y":
            res = apply_automatic_dump(confirmed=True)
            if res["success"]:
                print(f"\n[THÀNH CÔNG] {res['message']}\n")
                return 0
            else:
                print(f"\n[THẤT BÀI] {res['message']}\n")
                return 1
        else:
            print("\n[HUỶ BỎ] Người dùng đã huỷ thao tác sửa đổi registry.\n")
            return 0
    else:
        print("Ghi chú: Lệnh trên chỉ ĐỌC cấu hình. Để tự động bật ghi dump an toàn, hãy dùng:")
        print("         dumpanalyzer check-dump-config --apply\n")
        return 0


def cmd_validate_rules(args):
    """Kiểm tra cú pháp và tính hợp lệ của tất cả các file cấu hình và quy tắc YAML."""
    print_banner()
    print("\n--- KIỂM TRA TÍNH HỢP LỆ FILE QUY TẮC (Validate Rules) ---")

    is_valid, errors, summary = validate_rules_and_settings()
    if is_valid:
        print("[OK] TOÀN BỘ CÁC FILE QUY TẮC ĐỀU HỢP LỆ VÀ SẴN SÀNG SỬ DỤNG!")
        print("  - settings.yaml:          Hợp lệ")
        print(f"  - bugcheck_rules.yaml:    {summary.get('bugcheck_rules_count', 0)} quy tắc mã lỗi")
        print(f"  - driver_map.yaml:        {summary.get('driver_mappings_count', 0)} ánh xạ driver, {summary.get('ms_core_modules_count', 0)} module lõi Microsoft")
        print(f"  - event_rules.yaml:       {summary.get('event_rules_count', 0)} quy tắc sự kiện Event Log")
        print(f"  - event_categories.yaml:  {summary.get('event_categories_count', 0)} danh mục sự kiện IT")
        print(f"  - module_classes.yaml:    {'Hợp lệ' if summary.get('module_classes') else 'N/A'}")
        print(f"  - triage_rules.yaml:      {summary.get('triage_rules_count', 0)} quy tắc minidump triage")
        print(f"  - patterns.yaml:          {summary.get('patterns_count', 0)} mẫu hình đa crash")
        print("\nKhông phát hiện lỗi cú pháp hay thiếu trường bắt buộc nào.\n")
        return 0
    else:
        print(f"[X] PHÁT HIỆN {len(errors)} LỖI TRONG CÁC FILE CẤU HÌNH / QUY TẮC:")
        for idx, err in enumerate(errors, 1):
            print(f"  {idx}. {err}")
        print("\nVui lòng kiểm tra lại số dòng và sửa các lỗi trên trước khi tiếp tục.\n")
        return 1


def _print_finding_report(finding: Finding, crash: Crash, scored: Dict[str, Any]):
    """In báo cáo kết luận cho một crash đơn lẻ."""
    time_str = utc_to_local_str(crash.crash_time_utc)
    bc_str = crash.bugcheck_code or "N/A"
    bc_name = crash.bugcheck_name or "Chưa rõ"

    print("\n======================================================================")
    print(f"  KẾT LUẬN VỤ SẬP: Lúc {time_str} | Mã lỗi: {bc_str} ({bc_name})")
    print("======================================================================")
    print(f"Phân loại dump:   {crash.dump_type} (Phân tích bằng: {crash.analyzed_by})")
    print(f"Nghi vấn chính:   {get_suspect_label_vi(finding.suspect)} ({finding.score:.1f}%)")
    print(f"Độ tin cậy:       [{finding.confidence.upper()}]")
    if finding.evidence_ids:
        print(f"Bằng chứng số:    {', '.join(f'#{i}' for i in finding.evidence_ids)}")

    print("\n[XẾP HẠNG CÁC NHÓM NGUYÊN NHÂN]:")
    for susp, pct in scored.get("suspect_scores", [])[:4]:
        bar_len = int(pct / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        lbl = get_suspect_label_vi(susp)
        print(f"  {lbl:<36} : {bar} {pct:>5.1f}%")

    print("\n[GIẢI THÍCH NGUYÊN NHÂN (Rationale)]:")
    print(f"  {finding.rationale}")

    print("\n[CÁC BƯỚC KIỂM TRA ĐỀ XUẤT (Từ dễ đến khó)]:")
    for idx, step in enumerate(finding.next_steps, 1):
        print(f"  Bước {idx}: {step}")
    print("======================================================================\n")


def _print_machine_verdict_report(
    finding: Finding,
    scored: Dict[str, Any],
    crashes_with_evs: List[Tuple[Crash, List[Evidence]]],
):
    """In báo cáo kết luận tổng hợp theo máy tính."""
    crash_count = len(crashes_with_evs)
    print("\n======================================================================")
    print(f"  TỔNG HỢP CHẨN ĐOÁN HỆ THỐNG ({crash_count} LẦN SẬP ĐƯỢC PHÂN TÍCH)")
    print("======================================================================")
    print(f"Nguyên nhân hàng đầu: {get_suspect_label_vi(finding.suspect)} ({finding.score:.1f}%)")
    print(f"Mức độ tin cậy:       [{finding.confidence.upper()}]")

    if scored.get("is_conflicted"):
        print("\n[!] CẢNH BÁO MÂU THUẪN:")
        print(f"    {scored.get('conflict_note')}")

    if scored.get("patterns_matched"):
        print("\n[*] MẪU HÌNH NHẬN DIỆN ĐƯỢC:")
        for p in scored["patterns_matched"]:
            print(f"    - {p}")

    print("\n[XẾP HẠNG NGHI VẤN TỔNG HỢP]:")
    for susp, pct in scored.get("suspect_scores", [])[:5]:
        bar_len = int(pct / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        lbl = get_suspect_label_vi(susp)
        print(f"  {lbl:<36} : {bar} {pct:>5.1f}%")

    print("\n[GIẢI THÍCH NGUYÊN NHÂN (Rationale)]:")
    print(f"  {finding.rationale}")

    print("\n[HÀNH ĐỘNG KIỂM TRA KHUYẾN NGHỊ (Sắp xếp từ DỄ -> KHÓ)]:")
    for idx, step in enumerate(finding.next_steps, 1):
        print(f"  {idx}. {step}")

    print("\n[CHI TIẾT CÁC LẦN SẬP ĐÃ PHÂN TÍCH]:")
    col_t = 20
    col_code = 10
    col_name = 28
    col_by = 12
    hdr = f"{'Thời điểm (Giờ địa phương)':<{col_t}} | {'Mã lỗi':<{col_code}} | {'Tên lỗi':<{col_name}} | {'Phân tích bằng':<{col_by}}"
    sep = "-" * len(hdr) + "-" * 10
    print(sep)
    print(hdr)
    print(sep)
    for c, _ in crashes_with_evs:
        t_loc = utc_to_local_str(c.crash_time_utc)[:col_t]
        c_code = (c.bugcheck_code or "N/A")[:col_code]
        c_name = (c.bugcheck_name or "Chưa rõ")[:col_name]
        c_by = c.analyzed_by[:col_by]
        print(f"{t_loc:<{col_t}} | {c_code:<{col_code}} | {c_name:<{col_name}} | {c_by:<{col_by}}")
    print(sep)
    print("======================================================================\n")


def cmd_verdict(args):
    """Chấm điểm và đưa ra kết luận chẩn đoán nguyên nhân sập cho từng crash hoặc toàn bộ máy."""
    print_banner()
    print("\n--- KẾT LUẬN CHẨN ĐOÁN NGUYÊN NHÂN (Verdict Engine) ---")

    is_valid, errs, _ = validate_rules_and_settings()
    if not is_valid:
        print("[X] Không thể đưa ra kết luận vì file quy tắc YAML có lỗi:")
        for e in errs:
            print(f"  * {e}")
        return 1

    rules = load_all_rules()
    settings = load_settings()
    db = Database()

    # 1. Trường hợp chỉ định crash_id cụ thể
    if getattr(args, "crash_id", None):
        crash_data = db.get_crash_by_id(args.crash_id)
        if not crash_data:
            print(f"[X] Không tìm thấy bản ghi crash với ID = {args.crash_id} trong CSDL.")
            db.close()
            return 1

        ev_dicts = db.get_evidences_by_crash(args.crash_id)
        crash_obj = Crash(
            id=crash_data["id"],
            machine_id=crash_data.get("machine_id"),
            dump_path=crash_data.get("dump_path", ""),
            dump_sha256=crash_data.get("dump_sha256", ""),
            dump_type=crash_data.get("dump_type", "mini"),
            crash_time_utc=crash_data.get("crash_time_utc"),
            bugcheck_code=crash_data.get("bugcheck_code", ""),
            bugcheck_name=crash_data.get("bugcheck_name", ""),
            p1=crash_data.get("p1", ""),
            p2=crash_data.get("p2", ""),
            p3=crash_data.get("p3", ""),
            p4=crash_data.get("p4", ""),
            image_name=crash_data.get("image_name", ""),
            module_name=crash_data.get("module_name", ""),
            process_name=crash_data.get("process_name", ""),
            failure_bucket_id=crash_data.get("failure_bucket_id", ""),
            uptime_seconds=crash_data.get("uptime_seconds", 0),
            cdb_raw_output=crash_data.get("cdb_raw_output", ""),
            analyzed_by=crash_data.get("analyzed_by", "none"),
            suspect_driver=crash_data.get("suspect_driver", ""),
        )
        ev_objs = [
            Evidence(
                id=e["id"],
                crash_id=e["crash_id"],
                kind=e["kind"],
                source=e["source"],
                event_id=e["event_id"],
                time_utc=e["time_utc"],
                summary=e["summary"],
                detail=e["detail"],
            )
            for e in ev_dicts
        ]

        scored = score_single_crash(crash_obj, ev_objs, rules, settings)
        finding = generate_crash_finding(crash_obj, scored, rules)
        db.insert_finding(finding)

        _print_finding_report(finding, crash_obj, scored)
        db.close()
        return 0

    # 2. Trường hợp đánh giá theo máy hoặc toàn bộ crash
    machine_id = None
    if getattr(args, "machine", None):
        m = db.get_machine_by_hostname(args.machine)
        if m:
            machine_id = m["id"]
        else:
            print(f"[*] Máy '{args.machine}' chưa có bản ghi cấu hình riêng trong CSDL, sẽ quét theo thời gian...")

    from_d = getattr(args, "from_date", None)
    to_d = getattr(args, "to_date", None)
    crashes_dicts = db.get_crashes_by_machine(
        machine_id=machine_id,
        from_date=from_d,
        to_date=to_d,
    )

    if not crashes_dicts:
        print("[!] Không tìm thấy dữ liệu sập nào phù hợp trong CSDL.")
        db.close()
        return 0

    crashes_with_evs = []
    for cd in crashes_dicts:
        c_obj = Crash(
            id=cd["id"],
            machine_id=cd.get("machine_id"),
            dump_path=cd.get("dump_path", ""),
            dump_sha256=cd.get("dump_sha256", ""),
            dump_type=cd.get("dump_type", "mini"),
            crash_time_utc=cd.get("crash_time_utc"),
            bugcheck_code=cd.get("bugcheck_code", ""),
            bugcheck_name=cd.get("bugcheck_name", ""),
            p1=cd.get("p1", ""),
            p2=cd.get("p2", ""),
            p3=cd.get("p3", ""),
            p4=cd.get("p4", ""),
            image_name=cd.get("image_name", ""),
            module_name=cd.get("module_name", ""),
            process_name=cd.get("process_name", ""),
            failure_bucket_id=cd.get("failure_bucket_id", ""),
            uptime_seconds=cd.get("uptime_seconds", 0),
            cdb_raw_output=cd.get("cdb_raw_output", ""),
            analyzed_by=cd.get("analyzed_by", "none"),
            suspect_driver=cd.get("suspect_driver", ""),
        )
        ev_dicts = db.get_evidences_by_crash(cd["id"])
        ev_objs = [
            Evidence(
                id=e["id"],
                crash_id=e["crash_id"],
                kind=e["kind"],
                source=e["source"],
                event_id=e["event_id"],
                time_utc=e["time_utc"],
                summary=e["summary"],
                detail=e["detail"],
            )
            for e in ev_dicts
        ]
        crashes_with_evs.append((c_obj, ev_objs))

    # Chấm điểm tổng hợp máy
    scored_machine = score_machine_crashes(crashes_with_evs, rules, settings)
    m_finding = generate_machine_finding(machine_id, scored_machine, rules)
    db.insert_finding(m_finding)

    _print_machine_verdict_report(m_finding, scored_machine, crashes_with_evs)
    db.close()
    return 0



def cmd_analyze(args):
    """Phân tích chuyên sâu file dump bằng cdb.exe (!analyze -v) và lưu output thô."""
    print_banner()
    settings = load_settings()
    db = Database()

    targets: List[Dict[str, Any]] = []

    if args.all:
        targets = db.get_unprocessed_crashes()
        print(f"\n[*] Đang tìm các file dump chưa phân tích cdb trong CSDL: Tìm thấy {len(targets)} bản ghi.")
    elif args.path:
        search_path = Path(args.path)
        if search_path.is_file():
            # Kiểm tra trong DB hoặc tạo mới
            sha256 = calculate_sha256(search_path)
            cached = db.get_crash_by_sha256(sha256)
            if cached:
                targets = [cached]
            else:
                h_info = parse_dump_header(search_path)
                db.insert_crash(Crash(
                    dump_path=str(search_path),

                    dump_sha256=sha256,
                    dump_type=h_info.dump_type,
                    crash_time_utc=h_info.crash_time_utc,
                    bugcheck_code=h_info.bugcheck_code,
                    bugcheck_name=h_info.bugcheck_name,
                    p1=h_info.p1, p2=h_info.p2, p3=h_info.p3, p4=h_info.p4,
                    analyzed_by="header_only",
                ))
                targets = [db.get_crash_by_sha256(sha256)]
        else:
            found = find_dumps([str(search_path)])
            for f in found:
                sha256 = calculate_sha256(f["path"])
                cached = db.get_crash_by_sha256(sha256)
                if cached:
                    targets.append(cached)
                else:
                    h_info = parse_dump_header(f["path"])
                    db.insert_crash(Crash(
                        dump_path=str(f["path"]),

                        dump_sha256=sha256,
                        dump_type=h_info.dump_type,
                        crash_time_utc=h_info.crash_time_utc,
                        bugcheck_code=h_info.bugcheck_code,
                        bugcheck_name=h_info.bugcheck_name,
                        p1=h_info.p1, p2=h_info.p2, p3=h_info.p3, p4=h_info.p4,
                        analyzed_by="header_only",
                    ))
                    targets.append(db.get_crash_by_sha256(sha256))
    else:
        print("\n[!] Hãy chỉ định '--all' để phân tích mọi dump chưa xử lý, hoặc '--path <đường_dẫn>'.")
        db.close()
        return 1

    if not targets:
        print("[OK] Không có file dump nào cần phân tích chuyên sâu.")
        db.close()
        return 0

    concurrency = args.concurrency or settings.get("max_parallel_cdb", 2)
    print(f"[*] Bắt đầu phân tích chuyên sâu {len(targets)} dump (Số luồng: {concurrency})...\n")

    results = []
    for item in targets:
        dump_path = item["dump_path"]
        res = analyze_dump_file(
            dump_path=dump_path,
            cdb_path=settings.get("cdb_path"),
            symbol_path=settings.get("symbol_path"),
            timeout_seconds=settings.get("cdb_timeout_seconds", 300),
        )

        cdb_res = res["cdb_result"]
        analyzed_by = res["analyzed_by"]

        # Cập nhật kết quả vào SQLite
        db.update_crash_cdb_results(
            crash_id=item["id"],
            image_name=cdb_res.image_name,
            module_name=cdb_res.module_name,
            process_name=cdb_res.process_name,
            failure_bucket_id=cdb_res.failure_bucket_id,
            uptime_seconds=cdb_res.uptime_seconds,
            cdb_raw_output=res["raw_output"],
            analyzed_by=analyzed_by,
            suspect_driver=cdb_res.suspect_driver,
        )

        results.append({
            "id": item["id"],
            "code": cdb_res.bugcheck_code or item.get("bugcheck_code", "N/A"),
            "name": cdb_res.bugcheck_name or item.get("bugcheck_name", "Không rõ"),
            "suspect": cdb_res.suspect_driver or cdb_res.image_name or "Chưa rõ",
            "process": cdb_res.process_name or "N/A",
            "bucket": cdb_res.failure_bucket_id or "N/A",
            "by": analyzed_by,
        })

    db.close()

    # In bảng tổng kết
    col_id = 4
    col_code = 10
    col_name = 30
    col_susp = 22
    col_proc = 14
    col_by = 12

    line_hdr = (
        f"{'ID':<{col_id}} | "
        f"{'Mã lỗi':<{col_code}} | "
        f"{'Tên lỗi':<{col_name}} | "
        f"{'Nghi vấn chính':<{col_susp}} | "
        f"{'Tiến trình':<{col_proc}} | "
        f"{'Phương thức':<{col_by}}"
    )
    sep = "-" * len(line_hdr) + "-" * 10
    print(sep)
    print(line_hdr)
    print(sep)
    for r in results:
        print(
            f"{r['id']:<{col_id}} | "
            f"{r['code']:<{col_code}} | "
            f"{r['name'][:col_name]:<{col_name}} | "
            f"{r['suspect'][:col_susp]:<{col_susp}} | "
            f"{r['process'][:col_proc]:<{col_proc}} | "
            f"{r['by']:<{col_by}}"
        )
    print(sep)
    print(f"Hoàn thành phân tích {len(results)} file dump.\n")
    return 0


def cmd_warmup_symbols(args):
    """Kiểm tra và tải trước Symbol Microsoft."""
    print_banner()
    print("\n--- TẢI TRƯỚC SYMBOLS MICROSOFT (Symbol Warmup) ---")
    settings = load_settings()
    res = warmup_symbols(
        cdb_path=settings.get("cdb_path"),
        symbol_path=settings.get("symbol_path"),
    )
    if res["success"]:
        print(f"[OK] {res['message']}\n")
        return 0
    else:
        print(f"[X] {res['message']}\n")
        return 1


def cmd_events(args):
    """Thu thập và hiển thị các sự kiện Event Log quan trọng, hỗ trợ phân loại, .evtx và phát hiện đột biến."""
    from dumpanalyzer.analyzer.eventlog_analyzer import (
        harvest_live_eventlog,
        harvest_evtx_eventlog,
        export_eventlog_to_excel,
        redact_sensitive_text,
    )

    print_banner()
    evtx_path = getattr(args, "evtx_path", None)
    if evtx_path:
        print(f"\n--- PHÂN TÍCH FILE / THƯ MỤC .EVTX: {evtx_path} ---")
        res = harvest_evtx_eventlog(
            evtx_path=evtx_path,
            from_date=getattr(args, "from_date", None),
            to_date=getattr(args, "to_date", None),
            debug_ps=getattr(args, "debug_ps", False),
        )
    else:
        print("\n--- THU THẬP & PHÂN TÍCH SỰ KIỆN EVENT LOG THEO CẤP ĐỘ ---")
        res = harvest_live_eventlog(
            from_date=getattr(args, "from_date", None),
            to_date=getattr(args, "to_date", None),
            debug_ps=getattr(args, "debug_ps", False),
        )

    for warn in res.warnings:
        print(f"[CẢNH BÁO] {warn}")

    if not res.events:
        print(f"[!] {res.source_description}: Không có sự kiện nào trong phạm vi quét.")
        return 0

    is_redact = getattr(args, "redact", False)
    print(f"[OK] {res.source_description}: Thu thập {res.total_events} sự kiện.")
    print(f"     • Critical: {res.level_counts.get('Critical', 0)} | Error: {res.level_counts.get('Error', 0)} | Warning: {res.level_counts.get('Warning', 0)} | Info: {res.level_counts.get('Information', 0)}")
    if is_redact:
        print("     • Đã bật chế độ che thông tin nhạy cảm (Tên người dùng, IP, Domain User).")

    # 1. Nếu người dùng chọn --spikes
    if getattr(args, "spikes", False):
        print("\n--- CÁC ĐỢT BÙNG PHÁT LỖI ĐỘT BIẾN (SPIKE ALERTS) ---")
        if not res.spikes:
            print("Không phát hiện đợt bùng phát lỗi bất thường nào.")
        else:
            for sp in res.spikes:
                print(f"[*] {sp.description}")
        return 0

    # 2. Nếu người dùng chọn --pre-crash
    if getattr(args, "pre_crash", False):
        print("\n--- NGỮ CẢNH CÁC LỖI TRƯỚC LẦN SẬP MÁY / TẮT BẤT THƯỜNG ---")
        if not res.pre_crash_contexts:
            print("Không ghi nhận sự kiện tắt máy bất thường nào (Event 41/6008).")
        else:
            for ctx in res.pre_crash_contexts:
                t_str = utc_to_local_str(ctx.crash_time_utc)
                print(f"\n[*] Lúc {t_str} - {ctx.crash_type}:")
                print(f"    {ctx.summary}")
                for idx, pe in enumerate(ctx.preceding_events, start=1):
                    p_msg = pe.raw_message.replace("\n", " ")[:80]
                    if is_redact:
                        p_msg = redact_sensitive_text(p_msg)
                    print(f"    [{idx}] {utc_to_local_str(pe.time_created_utc)} | {pe.level_name} | {pe.provider} ({pe.event_id}): {p_msg}")
        return 0

    # 3. Xuất file Excel nếu có yêu cầu
    if getattr(args, "export_excel", None):
        out_excel = export_eventlog_to_excel(res, args.export_excel, redact=is_redact)
        print(f"\n[OK] Đã xuất báo cáo chi tiết Event Log sang Excel: {out_excel}")

    # 4. In bảng sự kiện tổng quan
    col_t = 19
    col_lvl = 10
    col_cat = 22
    col_prov = 26
    col_id = 6
    col_msg = 75

    line_h = f"{'Thời điểm (Local)':<{col_t}} | {'Mức độ':<{col_lvl}} | {'Danh mục':<{col_cat}} | {'Nguồn (Provider)':<{col_prov}} | {'ID':<{col_id}} | {'Nội dung tóm tắt'}"
    sep = "-" * len(line_h) + "-" * 20
    print("\n" + sep)
    print(line_h)
    print(sep)
    for e in res.events[:100]:  # Giới hạn in 100 dòng trên màn hình CLI
        t_str = utc_to_local_str(e.time_created_utc)[:col_t]
        lvl_str = e.level_name[:col_lvl]
        cat_str = e.category_name[:col_cat]
        p_str = e.provider[:col_prov]
        id_str = str(e.event_id)[:col_id]
        msg = e.raw_message.strip().splitlines()[0] if e.raw_message else ""
        if is_redact:
            msg = redact_sensitive_text(msg)
        print(f"{t_str:<{col_t}} | {lvl_str:<{col_lvl}} | {cat_str:<{col_cat}} | {p_str:<{col_prov}} | {id_str:<{col_id}} | {msg[:col_msg]}")
    print(sep)
    if len(res.events) > 100:
        print(f"[...] Còn {len(res.events) - 100} sự kiện khác. Dùng --export-excel để xem trọn vẹn trong Excel.")

    # 5. Đối chiếu phát hiện crash không có dump trong CSDL cục bộ (khi chạy log máy)
    if not evtx_path:
        db = Database()
        events_dicts = [e.to_dict() for e in res.events]
        existing_crashes_dicts = db.list_crashes()
        existing_crashes = [
            Crash(
                id=d["id"],
                crash_time_utc=d["crash_time_utc"],
                dump_type=d["dump_type"],
                bugcheck_code=d["bugcheck_code"],
            )
            for d in existing_crashes_dicts
        ]

        correlator = Correlator()
        detected_log_only = correlator.detect_log_only_crashes(existing_crashes, events_dicts)
        if detected_log_only:
            print(f"\n[!] PHÁT HIỆN {len(detected_log_only)} VỤ SẬP HỆ THỐNG KHÔNG CÓ DUMP (Chế độ log_only):")
            for crash_obj, _ in detected_log_only:
                existing = db.get_crash_by_sha256(crash_obj.dump_sha256)
                if not existing:
                    c_id = db.insert_crash(crash_obj)
                else:
                    c_id = existing["id"]
                t_local = utc_to_local_str(crash_obj.crash_time_utc)
                code_str = crash_obj.bugcheck_code or "Không có BSOD (Tắt nguồn/treo cứng)"
                print(f"    * Lúc {t_local}: Mã lỗi = {code_str} | Tên: {crash_obj.bugcheck_name}")
                evidences = correlator.correlate_events_to_crash(crash_obj, events_dicts)
                for ev in evidences:
                    ev.crash_id = c_id
                    db.insert_evidence(ev)
        db.close()

    return 0


def cmd_batch(args):
    """Lệnh phân tích theo lô đa dump / đa máy tính (Batch & Fleet Analysis)."""
    import json
    from dumpanalyzer.analyzer.batch import FleetBatchAnalyzer

    target_dir = getattr(args, "dir", None) or "."
    path_obj = Path(target_dir).resolve()
    if not path_obj.exists() or not path_obj.is_dir():
        print(f"[X] Thư mục không tồn tại: {target_dir}")
        return 1

    print("\n--- PHÂN TÍCH THEO LÔ ĐA MÁY TÍNH (Fleet Analysis) ---")
    print(f"[*] Đang quét thư mục: {path_obj}")

    analyzer = FleetBatchAnalyzer()
    try:
        fleet_data = analyzer.analyze_fleet(path_obj)
    except Exception as e:
        print(f"[X] Lỗi trong quá trình phân tích theo lô: {e}")
        return 1

    print("\n[+] KẾT QUẢ TỔNG QUAN:")
    print(f"  * Tổng số máy tính nhận diện: {fleet_data['total_machines']}")
    print(f"  * Tổng số file dump sập: {fleet_data['total_crashes']}")

    # Cảnh báo driver diện rộng
    widespread = fleet_data.get("widespread_drivers", [])
    if widespread:
        print(f"\n[!] CẢNH BÁO: Phát hiện {len(widespread)} driver gây lỗi hàng loạt trên nhiều máy:")
        for item in widespread:
            m_list = ", ".join(item["affected_machines"])
            print(f"    - Driver '{item['driver']}': {item['total_crashes']} lần sập trên {item['affected_machines_count']} máy ({m_list})")
            print(f"      Khuyến nghị: {item['note']}")
    else:
        print("\n[*] Không phát hiện driver lỗi xuất hiện đồng loạt trên nhiều máy.")

    # Mã lỗi phổ biến
    top_bcs = fleet_data.get("top_bugchecks", [])
    if top_bcs:
        print("\n[*] Các mã lỗi xuất hiện nhiều nhất:")
        for bc, count in top_bcs[:5]:
            print(f"    - {bc}: {count} lần")

    # Danh sách máy
    print("\n[*] Tóm tắt kết luận từng máy:")
    for m in fleet_data.get("machines", []):
        v = m.get("verdict", {})
        print(f"    - Máy '{m['machine_name']}': {m['dump_count']} dump | Nghi ngờ: {v.get('primary_culprit', 'Chưa rõ')} ({v.get('top_score', 0)}%) | Tin cậy: {v.get('confidence', 'Chưa rõ')}")

    # Xuất báo cáo nếu có yêu cầu
    if getattr(args, "report_html", None):
        out_h = analyzer.export_fleet_html(fleet_data, args.report_html)
        print(f"\n[+] Đã xuất báo cáo HTML: {out_h}")

    if getattr(args, "report_excel", None):
        out_e = analyzer.export_fleet_excel(fleet_data, args.report_excel)
        print(f"[+] Đã xuất báo cáo Excel: {out_e}")

    if getattr(args, "json", None):
        json_out = Path(args.json).resolve()
        json_out.parent.mkdir(parents=True, exist_ok=True)
        data_to_save = dict(fleet_data)
        data_to_save["timestamp_utc"] = data_to_save["timestamp_utc"].isoformat()
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, ensure_ascii=False, indent=2, default=str)
        print(f"[+] Đã xuất dữ liệu JSON: {json_out}")

    return 0


def cmd_clean_workspace(args):
    """Lệnh dọn dẹp an toàn các file dump sao chép trong thư mục làm việc (workspace)."""
    from dumpanalyzer.collectors.dump_finder import cleanup_workspace
    from dumpanalyzer.core.config import load_settings, get_settings_path

    settings = load_settings(get_settings_path())
    ws_dir = getattr(args, "dir", None) or settings.get("working_dir", "./workspace")
    print("\n--- DỌN DẸP AN TOÀN THƯ MỤC LÀM VIỆC (WORKSPACE) ---")
    print(f"[*] Thư mục: {ws_dir}")
    print("[!] LƯU Ý: Thao tác này chỉ xoá các file copy tạm thời, TUYỆT ĐỐI KHÔNG ẢNH HƯỞNG TỚI FILE DUMP GỐC.")

    deleted = cleanup_workspace(ws_dir)
    print(f"[+] Hoàn tất! Đã xoá an toàn {deleted} file dump tạm trong workspace.\n")
    return 0


def cmd_feedback(args):

    """Quản lý và thống kê phản hồi kết luận từ kỹ thuật viên (Phần 2.1)."""
    db = Database()
    action = getattr(args, "feedback_action", "stats")

    if action == "add":
        verdict = args.verdict.strip().lower()
        if verdict not in ("dung", "sai", "chua_ro"):
            print("[!] Lỗi: verdict phải là một trong: 'dung', 'sai', 'chua_ro'.")
            db.close()
            return 1

        m_id = None
        if getattr(args, "machine", None):
            conn = db._get_connection()
            cur = conn.execute("SELECT id FROM machine WHERE hostname = ?", (args.machine,))
            row = cur.fetchone()
            if row:
                m_id = row["id"]

        ref = getattr(args, "ref", None) or 1
        fid = db.insert_feedback(
            machine_id=m_id,
            analysis_ref=int(ref),
            predicted_group=getattr(args, "predicted_group", "") or "unknown",
            predicted_confidence=getattr(args, "predicted_confidence", "") or "trung bình",
            verdict=verdict,
            actual_cause=getattr(args, "actual_cause", "") or "",
            note=getattr(args, "note", "") or "",
        )
        print(f"[OK] Đã ghi nhận phản hồi #{fid}: Đánh giá [{verdict.upper()}] cho phân tích #{ref}.")
        db.close()
        return 0

    elif action == "list":
        limit = int(getattr(args, "limit", 20) or 20)
        items = db.list_feedback(limit=limit)
        print(f"\n--- DANH SÁCH {len(items)} PHẢN HỒI GẦN NHẤT ---")
        if not items:
            print("Chưa có phản hồi nào được ghi nhận.")
        else:
            print(f"{'ID':<4} | {'Máy':<12} | {'Ref':<6} | {'Đánh giá':<10} | {'Nguyên nhân thực tế':<20} | {'Ghi chú'}")
            print("-" * 75)
            for it in items:
                v_lbl = it['verdict'].upper()
                print(f"{it['id']:<4} | {it.get('machine_id', 0):<12} | #{it.get('analysis_ref', 0):<5} | {v_lbl:<10} | {it.get('actual_cause', ''):<20} | {it.get('note', '')}")
        print()
        db.close()
        return 0

    elif action == "stats":
        stats = db.get_feedback_stats()
        total = stats.get("total_count", stats.get("total", 0))
        print("\n--- THỐNG KÊ ĐỘ CHÍNH XÁC KẾT LUẬN (FEEDBACK STATS) ---")
        print(f"Tổng số ca đã đánh giá: {total}")
        v_counts = stats["verdict_counts"]
        print(f"  * Đúng:     {v_counts.get('dung', 0)}")
        print(f"  * Sai:      {v_counts.get('sai', 0)}")
        print(f"  * Chưa rõ:  {v_counts.get('chua_ro', 0)}")

        if total < 10:
            print("\n[!] Chưa đủ dữ liệu đánh giá độ chính xác (cần tối thiểu 10 ca có phản hồi).")
        else:
            acc = stats.get("accuracy_rate")
            print(f"\n[+] TỶ LỆ KẾT LUẬN CHÍNH XÁC (Hạng 1): {acc}%")

        if stats.get("by_confidence"):
            print("\nPhân bổ theo mức độ tin cậy được hệ thống dự đoán:")
            for conf, c_stat in stats["by_confidence"].items():
                print(f"  - [{conf.upper()}]: Tổng {c_stat['total']} ca | Đúng: {c_stat.get('dung', 0)}, Sai: {c_stat.get('sai', 0)}, Chưa rõ: {c_stat.get('chua_ro', 0)}")

        print()
        db.close()
        return 0


def cmd_fleet(args):
    """Phân tích các sự cố lan rộng trên toàn bộ đội máy tính trong cơ sở dữ liệu (Phần 2.3)."""
    from dumpanalyzer.engine.fleet import analyze_fleet_crashes
    settings = load_settings()
    rules = load_all_rules()
    db = Database()

    window = getattr(args, "window", None)
    min_m = getattr(args, "min_machines", None)
    if window:
        settings["fleet_window_days"] = int(window)
    if min_m:
        settings["fleet_min_machines"] = int(min_m)

    res = analyze_fleet_crashes(db, settings, rules)
    print("\n======================================================================")
    print("  PHÂN TÍCH SỰ CỐ DIỆN RỘNG TOÀN ĐỘI MÁY (FLEET ANALYSIS)")
    print("======================================================================")
    print(f"Khung thời gian quét: Trong vòng {res['window_days']} ngày gần nhất")
    print(f"Ngưỡng phát hiện:     Xuất hiện trên >= {res['min_machines']} máy tính khác nhau")
    print(f"Tổng số vụ sập quét: {res['total_crashes_in_window']} vụ sập trong CSDL\n")

    b_list = res.get("fleet_buckets", [])
    print(f"[1] FAILURE_BUCKET_ID XUẤT HIỆN TRÊN NHIỀU MÁY ({len(b_list)} nhóm):")
    if not b_list:
        print("  Không phát hiện mã bucket nào xuất hiện trên nhiều máy.")
    else:
        for b in b_list:
            m_str = ", ".join(b["machines"])
            print(f"  * Bucket: {b['bucket_id']}")
            print(f"    - Ảnh hưởng: {b['machine_count']} máy ({m_str})")
            print(f"    - Số vụ sập: {b['crash_count']} lần")

    d_list = res.get("fleet_drivers", [])
    print(f"\n[2] DRIVER BÊN THỨ BA GÂY LỖI TRÊN NHIỀU MÁY ({len(d_list)} driver):")
    if not d_list:
        print("  Không phát hiện driver bên thứ ba nào gây crash hàng loạt.")
    else:
        for d in d_list:
            m_str = ", ".join(d["machines"])
            print(f"  * Driver: {d['driver']}")
            print(f"    - Ảnh hưởng: {d['machine_count']} máy ({m_str})")
            print(f"    - Số vụ sập: {d['crash_count']} lần")

    print("======================================================================\n")
    db.close()
    return 0


def cmd_asset(args):
    """Nhập danh sách thiết bị và lịch sử sửa chữa từ file CSV (Phần 1.4)."""
    from dumpanalyzer.collectors.asset_info import import_asset_csv
    db = Database()
    csv_path = args.csv_file
    print("\n--- NHẬP DANH SÁCH THIẾT BỊ TỪ FILE CSV (AppSheet Export) ---")
    print(f"[*] Đường dẫn file: {csv_path}")

    res = import_asset_csv(csv_path, db)
    if res.get("errors"):
        print("\n[!] Lỗi khi xử lý file CSV:")
        for err in res["errors"]:
            print(f"  - {err}")
        db.close()
        return 1

    print(f"\n[OK] Đã xử lý {res['total_rows']} dòng dữ liệu:")
    print(f"  * Nhập thành công: {res['imported_count']} thiết bị")
    print(f"  * Bỏ qua:          {res['skipped_count']} dòng")
    db.close()
    return 0


def cmd_dump_readiness(args):
    """Báo cáo khả năng sẵn sàng ghi dump của máy cục bộ (Đợt 04)."""
    db = Database()
    try:
        report = collect_dump_readiness(db=db)
    finally:
        db.close()

    if getattr(args, "json", False):
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        if getattr(args, "out", None):
            Path(args.out).write_text(json_str, encoding="utf-8")
            print(f"[OK] Đã ghi báo cáo JSON ra: {args.out}")
        else:
            print(json_str)
        return 0

    print_banner()
    print("\n======================================================================")
    print("      BÁO CÁO KHẢ NĂNG SẴN SÀNG GHI DUMP (DUMP READINESS)")
    print("======================================================================")
    print(f"Máy tính:           {report.get('hostname')} ({report.get('os', {}).get('caption')})")
    print(f"Thời điểm thu thập: {report.get('collected_at_utc')}")
    print(f"Quyền chạy:         {'Administrator' if report.get('is_admin') else 'User thường (NOT_ADMIN)'}")

    res = report.get("result", {})
    status = res.get("status", "UNKNOWN")
    proof = res.get("proof_level", "none")
    proof_str = "Đã có bằng chứng ghi dump thành công" if proof == "evidence_of_success" else "Chưa có bằng chứng thực tế"

    print("\n----------------------------------------------------------------------")
    print(f"TRẠNG THÁI TỔNG:    [{status}]")
    print(f"Mức chứng minh:     {proof_str}")
    print(f"Tóm tắt:            {res.get('summary')}")
    print("----------------------------------------------------------------------")

    reg = report.get("registry", {})
    cde = reg.get("crash_dump_enabled")
    mode_desc = CRASH_DUMP_MODES.get(cde, "Không xác định") if cde is not None else "Không tồn tại"
    print(f"\n1. Cấu hình Registry:     CrashDumpEnabled = {cde} ({mode_desc})")
    print(f"   Đọc thành công:        {'Có' if reg.get('read_ok') else 'Không'}")

    pf = report.get("pagefile", {})
    print(f"\n2. Bộ nhớ ảo (Pagefile):  Trạng thái: {pf.get('state', 'unknown').upper()}")
    print(f"   Dung lượng ổ C:        {pf.get('system_drive_size_mb', 0)} MB")
    print(f"   Tự động quản lý:       {'Có' if pf.get('automatic_managed') else 'Không'}")

    disk = report.get("disk", {})
    print(f"\n3. Ổ đĩa & RAM:           Ổ hệ thống {disk.get('system_drive')}: Trống {disk.get('free_gb', 0)} GB")
    print(f"   Dung lượng RAM:        {report.get('ram_gb', 0)} GB")

    vm = report.get("volmgr", {})
    if vm.get("last_failure_utc"):
        print(f"\n4. Lỗi ghi dump (volmgr): Lỗi gần nhất lúc {vm.get('last_failure_utc')}")
    if vm.get("last_success_utc"):
        print(f"   Ghi thành công:        Lần gần nhất lúc {vm.get('last_success_utc')}")

    gap = report.get("dump_gap")
    if gap and gap.get("missing", 0) > 0:
        print(f"\n5. Đối chiếu sự cố (Gap): Thiếu {gap.get('missing')} file dump so với {gap.get('expected_bsod')} lần BSOD Event 41")

    rcs = res.get("reason_codes", [])
    if rcs:
        print("\nDANH SÁCH LÝ DO VÀ CẢNH BÁO:")
        for idx, rc in enumerate(rcs, 1):
            print(f"  {idx}. [{rc.get('level', '').upper()}] {rc.get('code')}: {rc.get('detail')}")

    recs = res.get("recommendations", [])
    if recs:
        print("\nKHUYẾN NGHỊ HÀNH ĐỘNG:")
        for idx, rec in enumerate(recs, 1):
            print(f"  * {rec}")

    act = report.get("enable_action", {})
    print(f"\nKhả năng bật ghi dump:  {'CHO PHÉP' if act.get('allowed') else 'BỊ CHẶN'}")
    if not act.get("allowed") and act.get("blocked_by"):
        print(f"Lý do chặn:             {', '.join(act.get('blocked_by'))}")

    print("======================================================================\n")

    if getattr(args, "out", None):
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        Path(args.out).write_text(json_str, encoding="utf-8")
        print(f"[OK] Đã xuất báo cáo ra file: {args.out}")

    return 0


def cmd_dump_enable(args):
    """Thực hiện bật ghi dump an toàn cho máy cục bộ (Đợt 04)."""
    print_banner()
    mode = getattr(args, "mode", 7) or 7

    # 1. Kiểm tra quyền Admin (Exit code 3)
    from dumpanalyzer.core.config import is_running_as_admin
    if not is_running_as_admin():
        print("\n[!] LỖI: Cần quyền Administrator để thay đổi cấu hình Registry hệ thống.")
        print("    Vui lòng nhấp chuột phải vào Terminal / Command Prompt và chọn 'Run as administrator'.")
        return 3

    # 2. Đánh giá khả năng bật
    db = Database()
    try:
        readiness = collect_dump_readiness(target_mode=mode, db=db)
    finally:
        db.close()

    act = readiness.get("enable_action", {})
    if not act.get("allowed", False):
        print("\n[X] KHÔNG THỂ BẬT GHI DUMP THEO MA TRẬN QUYẾT ĐỊNH:")
        for blk in act.get("blocked_by", []):
            print(f"  - {blk}")
        print("\nVui lòng khắc phục các điều kiện trên trước khi bật ghi dump.")
        return 5

    # 3. Xác nhận tương tác nếu không có --yes
    if not getattr(args, "yes", False):
        hostname = readiness.get("hostname", "Cục bộ")
        cur_cde = readiness.get("registry", {}).get("crash_dump_enabled")
        cur_desc = CRASH_DUMP_MODES.get(cur_cde, "Không xác định") if cur_cde is not None else "Chưa có cấu hình"
        target_desc = CRASH_DUMP_MODES.get(mode, f"Chế độ {mode}")

        print("\n======================================================================")
        print(f"          XÁC NHẬN BẬT GHI DUMP CHO MÁY: {hostname}")
        print("======================================================================")
        print(f"Hiện trạng:  CrashDumpEnabled = {cur_cde} ({cur_desc})")
        print(f"Sẽ đổi thành: CrashDumpEnabled = {mode} ({target_desc})")
        print("Sao lưu:     Tự động tạo bản sao lưu .json và .reg đầy đủ trước khi sửa.")
        print("LƯU Ý:       Cần KHỞI ĐỘNG LẠI MÁY để cấu hình có hiệu lực.")
        print("             Phần mềm TUYỆT ĐỐI KHÔNG tự khởi động lại máy.")
        if act.get("needs_confirm_notes"):
            print("Cảnh báo:   " + "\n             ".join(act.get("needs_confirm_notes")))
        print("======================================================================")

        try:
            ans = input("\nBạn có chắc chắn muốn thực hiện thay đổi này? (y/N): ").strip().lower()
        except EOFError:
            ans = "n"

        if ans not in ("y", "yes"):
            print("\n[!] Đã huỷ thao tác. Không có thay đổi nào được thực hiện.")
            return 4

    # 4. Thực thi bật dump
    db = Database()
    try:
        res = enable_crash_dump(target_mode=mode, confirmed=True, actor="cli_admin", db=db)
    finally:
        db.close()

    if res.get("success"):
        print(f"\n[OK] {res.get('message')}\n")
        if not res.get("changed", True):
            return 2
        return 0
    else:
        print(f"\n[X] LỖI: {res.get('message')}\n")
        return 1


def cmd_dump_rollback(args):
    """Hoàn tác cấu hình ghi dump từ bản sao lưu JSON (Đợt 04)."""
    print_banner()
    from dumpanalyzer.core.config import is_running_as_admin
    if not is_running_as_admin():
        print("\n[!] LỖI: Cần quyền Administrator để hoàn tác cấu hình Registry.")
        return 3

    backup_path = args.backup
    if not Path(backup_path).is_file():
        print(f"\n[!] LỖI: Không tìm thấy file sao lưu JSON tại: {backup_path}")
        return 1

    if not getattr(args, "yes", False):
        print("\n======================================================================")
        print("          XÁC NHẬN HOÀN TÁC CẤU HÌNH CRASHCONTROL")
        print("======================================================================")
        print(f"File sao lưu: {backup_path}")
        print("LƯU Ý:        Cần KHỞI ĐỘNG LẠI MÁY để Windows áp dụng lại cấu hình cũ.")
        print("======================================================================")
        try:
            ans = input("\nBạn có chắc chắn muốn hoàn tác về trạng thái trong file này? (y/N): ").strip().lower()
        except EOFError:
            ans = "n"

        if ans not in ("y", "yes"):
            print("\n[!] Đã huỷ thao tác hoàn tác.")
            return 4

    db = Database()
    try:
        res = rollback_crash_dump(backup_path, confirmed=True, actor="cli_admin", db=db)
    finally:
        db.close()

    if res.get("success"):
        print(f"\n[OK] {res.get('message')}\n")
        return 0
    else:
        print(f"\n[X] LỖI: {res.get('message')}\n")
        return 1


def cmd_dump_package(args):
    """Tạo gói triển khai bật ghi dump hàng loạt cho đội máy (Đợt 04)."""
    print_banner()
    out_dir = args.out
    print("\n--- TẠO GÓI TRIỂN KHAI BẬT GHI DUMP (DEPLOYMENT PACKAGE) ---")
    print(f"[*] Thư mục đích: {out_dir}")

    try:
        pkg_path = generate_deployment_package(out_dir)
        print("\n[OK] ĐÃ TẠO GÓI TRIỂN KHAI THÀNH CÔNG:")
        print(f"  - Script bật:     {pkg_path / 'Enable-CrashDump.ps1'}")
        print(f"  - Script hoàn tác: {pkg_path / 'Rollback-CrashDump.ps1'}")
        print(f"  - Tài liệu HD:    {pkg_path / 'README_TRIEN_KHAI.txt'}")
        print("\nBạn có thể copy thư mục này vào mạng chia sẻ hoặc cấu hình GPO Startup Script.")
        return 0
    except Exception as e:
        print(f"\n[X] Lỗi khi tạo gói triển khai: {e}")
        return 1


def cmd_dump_fleet(args):
    """Tổng hợp trạng thái sẵn sàng ghi dump của toàn bộ đội máy tính (Đợt 04)."""
    print_banner()
    share_dir = args.dir
    print("\n--- TỔNG HỢP TRẠNG THÁI SẴN SÀNG ĐỘI MÁY (DUMP FLEET) ---")
    print(f"[*] Thư mục báo cáo chia sẻ: {share_dir}")

    db = Database()
    try:
        res = aggregate_fleet_reports(share_dir=share_dir, db=db)
    finally:
        db.close()

    summary = res.get("summary", {})
    print(f"\n[OK] Đã quét {res.get('total_files', 0)} tệp báo cáo:")
    print(f"  * Báo cáo hợp lệ:          {res.get('valid_reports', 0)}")
    print(f"  * Tổng số máy tính:        {summary.get('total_machines', 0)}")
    print(f"  * Tỷ lệ SẴN SÀNG (READY):  {summary.get('ready_rate', 0.0)}%")
    print(f"  * Đã bật, chờ reboot:      {summary.get('ready_pending_reboot_count', 0)}")
    print(f"  * Cần chú ý (ATTENTION):   {summary.get('attention_count', 0)}")
    print(f"  * Bị chặn (BLOCKED):       {summary.get('blocked_count', 0)}")
    print(f"  * Không xác định (UNKNOWN): {summary.get('unknown_count', 0)}")
    print(f"  * Báo cáo cũ (> 14 ngày):  {summary.get('stale_count', 0)}")

    top_reasons = summary.get("top_reasons", {})
    if top_reasons:
        print("\nTop các nguyên nhân phổ biến trong đội máy:")
        for r_code, count in list(top_reasons.items())[:5]:
            print(f"  - {r_code:<25}: {count} máy")

    if getattr(args, "export", None):
        try:
            excel_path = export_fleet_readiness_excel(res, args.export)
            print(f"\n[OK] Đã xuất báo cáo Excel đội máy ra: {excel_path}")
        except Exception as e:
            print(f"\n[!] Lỗi khi xuất Excel: {e}")

    return 0


def cmd_selftest(args):
    """Tự kiểm tra toàn diện phần mềm (quy tắc, CSDL, dump_config, gói đóng gói)."""
    print_banner()
    print("\n--- CHẠY TỰ KIỂM TRA HỆ THỐNG (SELFTEST) ---")
    all_ok = True

    # 1. Kiểm tra CSDL
    try:
        db = Database()
        conn = db._get_connection()
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cur.fetchall()}
        required_tables = {"crash", "evidence", "finding", "feedback", "dump_readiness", "dump_config_change"}
        missing = required_tables - tables
        if not missing:
            print("[OK] CSDL SQLite & Migrations: Hoàn hảo (đủ các bảng cần thiết)")
        else:
            print(f"[X] CSDL SQLite thiếu bảng: {missing}")
            all_ok = False
        db.close()
    except Exception as e:
        print(f"[X] Lỗi kiểm tra CSDL SQLite: {e}")
        all_ok = False

    # 2. Kiểm tra bộ quy tắc YAML
    try:
        is_valid, errs, summary = validate_rules_and_settings()
        if is_valid:
            print(f"[OK] Quy tắc chẩn đoán & Cấu hình: Hợp lệ ({summary.get('bugcheck_rules_count', 0)} bugchecks, dump_readiness.yaml)")
        else:
            print(f"[X] Phát hiện {len(errs)} lỗi trong file quy tắc:")
            for err in errs:
                print(f"  - {err}")
            all_ok = False
    except Exception as e:
        print(f"[X] Lỗi kiểm tra quy tắc: {e}")
        all_ok = False

    # 3. Kiểm tra module dump_readiness
    try:
        report = collect_dump_readiness()
        st = report.get("result", {}).get("status")
        if st in (STATUS_READY, STATUS_READY_PENDING_REBOOT, STATUS_ATTENTION, STATUS_BLOCKED, STATUS_UNKNOWN):
            print(f"[OK] Module Sẵn sàng ghi dump (dump_config): Trạng thái máy [{st}]")
        else:
            print(f"[X] Module dump_config trả về trạng thái lạ: {st}")
            all_ok = False
    except Exception as e:
        print(f"[X] Lỗi kiểm tra dump_config: {e}")
        all_ok = False

    # 4. Kiểm tra bộ đọc Minidump Triage (Đợt 05) bằng tệp tổng hợp trong bộ nhớ
    try:
        import tempfile
        from dumpanalyzer.analyzer._selftest_fixture import build_synthetic_triage
        from dumpanalyzer.analyzer.triage_reader import read_triage
        syn_data = build_synthetic_triage()
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            tf.write(syn_data)
            tf.flush()
            syn_path = tf.name
        t_res = read_triage(syn_path)
        try:
            Path(syn_path).unlink(missing_ok=True)
        except Exception:
            pass

        if t_res.ok and t_res.header.get("bugcheck_code") == "0x23" and len(t_res.modules) >= 5:
            print("[OK] Bộ đọc Minidump Triage nội bộ (triage_reader): Hoàn hảo (đọc tốt dữ liệu tổng hợp)")
        else:
            print(f"[X] Bộ đọc triage_reader trả về kết quả không khớp: ok={t_res.ok}, warnings={t_res.warnings}")
            all_ok = False
    except Exception as e:
        print(f"[X] Lỗi kiểm tra triage_reader: {e}")
        all_ok = False

    print("\n----------------------------------------------------------------------")
    if all_ok:
        print("[OK] TOÀN BỘ CÁC BÀI TỰ KIỂM TRA ĐỀU THÀNH CÔNG (100% PASSED)!")
        return 0
    else:
        print("[X] PHÁT HIỆN SỰ CỐ TRONG BÀI TỰ KIỂM TRA. VUI LÒNG KIỂM TRA LẠI.")
        return 1


def cmd_triage_info(args):
    """Đọc và hiển thị thông tin minidump triage bằng bộ đọc nội bộ (không cần cdb)."""
    from dumpanalyzer.analyzer.triage_reader import read_triage
    dump_path = Path(args.dump_path)
    if not dump_path.exists():
        print(f"[X] File dump không tồn tại: {dump_path}", file=sys.stderr)
        return 1

    res = read_triage(dump_path)
    if getattr(args, "json", False):
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0

    print_banner()
    print(f"\n--- THÔNG TIN MINIDUMP TRIAGE (NỘI BỘ): {dump_path.name} ---")
    print(f"Trạng thái đọc: {'[OK]' if res.ok else '[LỖI]'}")
    if res.warnings:
        print("Cảnh báo:")
        for w in res.warnings:
            print(f"  - {w}")

    h = res.header
    print(f"OS Build: {h.get('os_build')} | Loại dump: {h.get('dump_type_name')} | Giờ sập (UTC): {h.get('system_time_utc')}")
    print(f"Mã Bug Check: {h.get('bugcheck_code')} (Tham số: {', '.join(h.get('params', []))})")

    if res.exception:
        ex = res.exception
        print(f"Ngoại lệ: {ex.get('code')} tại {ex.get('address')} ({ex.get('module')}+{ex.get('module_offset', '0x0')})")
        if ex.get("meaning"):
            print(f"  Ý nghĩa: {ex.get('meaning')}")

    if res.stack_modules_in_order:
        print(f"Module trong call stack (theo thứ tự): {', '.join(res.stack_modules_in_order)}")
    print(f"Số module đang nạp: {len(res.modules)} | Driver đã gỡ: {len(res.unloaded)}")
    if res.unloaded:
        print(f"  Các driver đã gỡ: {', '.join(res.unloaded[:15])}")
    return 0


def cmd_triage_compare(args):
    """Đối chiếu kết quả phân tích giữa bộ đọc triage nội bộ và cdb.exe."""
    from dumpanalyzer.analyzer.triage_reader import read_triage
    from dumpanalyzer.analyzer.cdb_runner import analyze_dump_file

    dump_path = Path(args.dump_path)
    if not dump_path.exists():
        print(f"[X] File dump không tồn tại: {dump_path}", file=sys.stderr)
        return 1

    print_banner()
    print(f"\n--- ĐỐI CHIẾU TRIAGE NỘI BỘ vs WINDBG CDB: {dump_path.name} ---\n")

    triage_res = read_triage(dump_path)
    cdb_res = analyze_dump_file(dump_path)

    t_hdr = triage_res.header
    c_res = cdb_res.get("cdb_result")

    t_bc = t_hdr.get("bugcheck_code", "N/A")
    c_bc = getattr(c_res, "bugcheck_code", "N/A") if c_res else "N/A"

    t_exc_mod = triage_res.exception.get("module", "N/A")
    c_mod = getattr(c_res, "module_name", "N/A") if c_res else "N/A"

    t_exc_addr = triage_res.exception.get("address", "N/A")
    c_addr = getattr(c_res, "p4", "N/A") if c_res else "N/A"

    print(f"{'Thuộc tính':<25} | {'Triage Nội Bộ':<28} | {'WinDbg cdb':<28} | {'Trạng thái'}")
    print("-" * 95)

    def _comp(label, val1, val2):
        s1 = str(val1).upper()
        s2 = str(val2).upper()
        match = (s1 == s2) or (s1 in s2) or (s2 in s1)
        st = "[KHỚP]" if match else "[KHÁC NHAU]"
        print(f"{label:<25} | {str(val1):<28} | {str(val2):<28} | {st}")

    _comp("Mã Bug Check", t_bc, c_bc)
    _comp("Module ngoại lệ/sập", t_exc_mod, c_mod)
    _comp("Địa chỉ ngoại lệ (RIP)", t_exc_addr, c_addr)
    _comp("Giờ sập (UTC)", t_hdr.get("system_time_utc", "N/A"), getattr(c_res, "crash_time_utc", "N/A"))

    print("\n[OK] Hoàn tất đối chiếu.")
    return 0


def build_parser() -> argparse.ArgumentParser:

    """Xây dựng bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        prog="dumpanalyzer",
        description="DumpAnalyzer - Phân tích BSOD dump kết hợp Windows Event Log\nTác giả phát triển: Lilbow",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"DumpAnalyzer v{__version__} - Tác giả phát triển: Lilbow",
        help="Hiển thị phiên bản hiện tại của phần mềm",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="Lệnh khả dụng",
        description="Chọn lệnh cần thực thi",
        help="Nhập 'dumpanalyzer <lệnh> --help' để xem chi tiết từng lệnh",
    )

    # Subcommand: check-env
    parser_check = subparsers.add_parser(
        "check-env",
        help="Kiểm tra môi trường hệ thống (cdb.exe, quyền Admin, thư mục dump)",
    )
    parser_check.set_defaults(func=cmd_check_env)

    # Subcommand: scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Quét và đọc mã lỗi từ header file dump (không cần cdb.exe)",
    )
    parser_scan.add_argument(
        "--path",
        help="Đường dẫn thư mục hoặc file dump cần quét (ví dụ: 'C:\\Windows\\Minidump' hoặc file cụ thể)",
    )
    parser_scan.add_argument(
        "--from",
        dest="from_date",
        help="Chỉ quét các file dump từ ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--to",
        dest="to_date",
        help="Chỉ quét các file dump đến ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--force",
        action="store_true",
        help="Bỏ qua cache SHA256, bắt buộc đọc lại và cập nhật cơ sở dữ liệu",
    )
    parser_scan.add_argument(
        "--save-cdb-samples",
        action="store_true",
        help="Lưu lại toàn bộ output thô cdb vào thư mục workspace/cdb_samples để gửi mẫu phân tích",
    )
    parser_scan.set_defaults(func=cmd_scan)

    # Subcommand: check-dump-config (Phase 1B)
    parser_dump_cfg = subparsers.add_parser(
        "check-dump-config",
        help="Kiểm tra khả năng ghi dump của Windows (CrashControl, Pagefile, Dung lượng đĩa, volmgr)",
    )
    parser_dump_cfg.add_argument(
        "--apply",
        action="store_true",
        help="Bật ghi dump tự động (CrashDumpEnabled = 7) có sao lưu và xác nhận an toàn",
    )
    parser_dump_cfg.set_defaults(func=cmd_check_dump_config)

    # Subcommand: analyze (Phase 2)
    parser_analyze = subparsers.add_parser(
        "analyze",
        help="Phân tích chuyên sâu bằng cdb.exe (!analyze -v) lấy stack trace và driver bên thứ ba",
    )
    parser_analyze.add_argument(
        "--all",
        action="store_true",
        help="Phân tích toàn bộ các file dump chưa xử lý trong CSDL",
    )
    parser_analyze.add_argument(
        "--path",
        help="Đường dẫn thư mục hoặc file dump cần phân tích chuyên sâu",
    )
    parser_analyze.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="Số tiến trình phân tích song song tối đa (mặc định: 2)",
    )
    parser_analyze.add_argument(
        "--save-cdb-samples",
        action="store_true",
        help="Lưu lại toàn bộ output thô cdb vào thư mục workspace/cdb_samples để gửi mẫu phân tích",
    )
    parser_analyze.set_defaults(func=cmd_analyze)


    # Subcommand: warmup-symbols (Phase 2)
    parser_warmup = subparsers.add_parser(
        "warmup-symbols",
        help="Tải trước Symbol Microsoft để tránh bị treo khi phân tích hàng loạt",
    )
    parser_warmup.set_defaults(func=cmd_warmup_symbols)

    # Subcommand: events (Phase 3)
    parser_events = subparsers.add_parser(
        "events",
        help="Đọc các sự kiện System Event Log quan trọng và phát hiện sập không có dump (log_only)",
    )
    parser_events.add_argument(
        "--from",
        dest="from_date",
        help="Lọc sự kiện từ ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_events.add_argument(
        "--to",
        dest="to_date",
        help="Lọc sự kiện đến ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_events.add_argument(
        "--evtx",
        dest="evtx_path",
        help="Đường dẫn file hoặc thư mục chứa file .evtx cần phân tích ngoại vi",
    )
    parser_events.add_argument(
        "--export-excel",
        dest="export_excel",
        help="Đường dẫn file Excel (.xlsx) để xuất báo cáo phân tích",
    )
    parser_events.add_argument(
        "--redact",
        dest="redact",
        action="store_true",
        help="Che thông tin nhạy cảm (Tên người dùng, IP, Domain User) để bảo mật",
    )
    parser_events.add_argument(
        "--spikes",
        dest="spikes",
        action="store_true",
        help="Chỉ hiển thị các đợt bùng phát lỗi bất thường (Spike Alerts)",
    )
    parser_events.add_argument(
        "--pre-crash",
        dest="pre_crash",
        action="store_true",
        help="Chỉ hiển thị các sự kiện cảnh báo/lỗi xảy ra ngay trước khi sập máy",
    )
    parser_events.add_argument(
        "--debug-ps",
        dest="debug_ps",
        action="store_true",
        help="In ra chi tiết script PowerShell và output thô để kiểm tra lỗi",
    )
    parser_events.set_defaults(func=cmd_events)

    # Subcommand: validate-rules (Phase 4)
    parser_val = subparsers.add_parser(
        "validate-rules",
        help="Kiểm tra cú pháp và tính hợp lệ của tất cả các file cấu hình và quy tắc YAML",
    )
    parser_val.set_defaults(func=cmd_validate_rules)

    # Subcommand: verdict (Phase 4)
    parser_verdict = subparsers.add_parser(
        "verdict",
        help="Chấm điểm, khoanh vùng nguyên nhân và đưa ra các bước kiểm tra từ dễ đến khó",
    )
    parser_verdict.add_argument(
        "--machine",
        help="Tên máy tính (hostname) cần tổng hợp kết luận",
    )
    parser_verdict.add_argument(
        "--crash-id",
        type=int,
        help="ID của một vụ sập cụ thể trong CSDL",
    )
    parser_verdict.add_argument(
        "--from",
        dest="from_date",
        help="Lọc vụ sập từ ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_verdict.add_argument(
        "--to",
        dest="to_date",
        help="Lọc vụ sập đến ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_verdict.set_defaults(func=cmd_verdict)

    # Subcommand: batch (Phase 6)
    parser_batch = subparsers.add_parser(
        "batch",
        help="Phân tích theo lô đa dump / đa máy tính, phát hiện driver lỗi hàng loạt",
    )
    parser_batch.add_argument(
        "--dir",
        default=".",
        help="Đường dẫn thư mục chứa dump của nhiều máy (mỗi thư mục con là một máy)",
    )
    parser_batch.add_argument(
        "--report-html",
        help="Đường dẫn xuất file báo cáo tổng hợp dạng HTML",
    )
    parser_batch.add_argument(
        "--report-excel",
        help="Đường dẫn xuất file báo cáo tổng hợp dạng Excel (.xlsx)",
    )
    parser_batch.add_argument(
        "--json",
        help="Đường dẫn xuất dữ liệu tổng hợp dạng file JSON",
    )
    parser_batch.set_defaults(func=cmd_batch)

    # Subcommand: clean-workspace (Phase 6)
    parser_clean = subparsers.add_parser(
        "clean-workspace",
        help="Dọn dẹp an toàn các file dump sao chép trong thư mục tạm workspace (không xoá file gốc)",
    )
    parser_clean.add_argument(
        "--dir",
        help="Đường dẫn thư mục làm việc cần dọn dẹp (mặc định lấy theo settings.yaml)",
    )
    parser_clean.set_defaults(func=cmd_clean_workspace)

    # Subcommand: feedback (Phần 2.1)
    parser_fb = subparsers.add_parser(
        "feedback",
        help="Ghi nhận và thống kê phản hồi kết luận từ kỹ thuật viên (add | list | stats)",
    )
    fb_subparsers = parser_fb.add_subparsers(dest="feedback_action", help="Thao tác phản hồi")

    fb_add = fb_subparsers.add_parser("add", help="Thêm phản hồi đánh giá kết luận")
    fb_add.add_argument("--verdict", required=True, choices=["dung", "sai", "chua_ro"], help="Đánh giá kết luận: dung, sai, chua_ro")
    fb_add.add_argument("--ref", type=int, default=1, help="Mã ID kết luận (Finding ID hoặc Crash ID)")
    fb_add.add_argument("--machine", help="Tên máy tính (hostname)")
    fb_add.add_argument("--predicted-group", help="Nhóm nguyên nhân dự đoán (gpu, ram, storage, ...)")
    fb_add.add_argument("--predicted-confidence", help="Mức độ tin cậy được dự đoán (cao, trung bình, thấp)")
    fb_add.add_argument("--actual-cause", help="Nguyên nhân thực tế sau khi sửa chữa/kiểm tra")
    fb_add.add_argument("--note", help="Ghi chú chi tiết của kỹ thuật viên")

    fb_list = fb_subparsers.add_parser("list", help="Liệt kê danh sách các phản hồi đã ghi nhận")
    fb_list.add_argument("--limit", type=int, default=20, help="Số lượng bản ghi tối đa (mặc định: 20)")
    fb_list.add_argument("--machine-id", type=int, help="Lọc theo ID máy tính")

    fb_subparsers.add_parser("stats", help="Thống kê tỷ lệ chính xác và phân bổ phản hồi")

    parser_fb.set_defaults(func=cmd_feedback)

    # Subcommand: fleet (Phần 2.3)
    parser_flt = subparsers.add_parser(
        "fleet",
        help="Phân tích tổng quan sự cố trên toàn bộ đội máy tính trong CSDL",
    )
    parser_flt.add_argument("--window", type=int, help="Khung thời gian quét (số ngày, mặc định 30)")
    parser_flt.add_argument("--min-machines", type=int, help="Ngưỡng số máy tối thiểu gặp cùng lỗi (mặc định 3)")
    parser_flt.set_defaults(func=cmd_fleet)

    # Subcommand: asset (Phần 1.4)
    parser_ast = subparsers.add_parser(
        "asset",
        help="Quản lý thông tin thiết bị và nhập danh sách từ AppSheet CSV",
    )
    ast_subparsers = parser_ast.add_subparsers(dest="asset_action", help="Thao tác asset")
    ast_import = ast_subparsers.add_parser("import", help="Nhập file CSV danh sách thiết bị xuất từ AppSheet/Google Sheets")
    ast_import.add_argument("csv_file", help="Đường dẫn tới file CSV danh sách thiết bị")
    parser_ast.set_defaults(func=cmd_asset)

    # ==================== ĐỢT 04: DUMP READINESS & SAFE ACTIONS ====================

    # Subcommand: dump-readiness (Phần 6.1)
    parser_readiness = subparsers.add_parser(
        "dump-readiness",
        help="Kiểm tra khả năng sẵn sàng ghi dump của máy cục bộ (trạng thái, bằng chứng, khuyến nghị)",
    )
    parser_readiness.add_argument(
        "--json",
        action="store_true",
        help="Xuất báo cáo định dạng chuẩn JSON ra màn hình",
    )
    parser_readiness.add_argument(
        "--out",
        help="Đường dẫn file lưu báo cáo JSON",
    )
    parser_readiness.set_defaults(func=cmd_dump_readiness)

    # Subcommand: dump-enable (Phần 6.1)
    parser_enable = subparsers.add_parser(
        "dump-enable",
        help="Bật ghi dump an toàn cục bộ có sao lưu đầy đủ và kiểm tra ma trận quyết định",
    )
    parser_enable.add_argument(
        "--yes",
        action="store_true",
        help="Tự động đồng ý xác nhận, không hỏi lại [y/N]",
    )
    parser_enable.add_argument(
        "--mode",
        type=int,
        choices=[3, 7],
        default=7,
        help="Chế độ dump mục tiêu: 7 (Automatic - khuyến nghị) hoặc 3 (Small dump 256KB)",
    )
    parser_enable.set_defaults(func=cmd_dump_enable)

    # Subcommand: dump-rollback (Phần 6.1)
    parser_rollback = subparsers.add_parser(
        "dump-rollback",
        help="Hoàn tác 100% cấu hình CrashControl từ file sao lưu JSON",
    )
    parser_rollback.add_argument(
        "--backup",
        required=True,
        help="Đường dẫn file sao lưu JSON được tạo khi bật ghi dump",
    )
    parser_rollback.add_argument(
        "--yes",
        action="store_true",
        help="Tự động đồng ý hoàn tác, không hỏi lại [y/N]",
    )
    parser_rollback.set_defaults(func=cmd_dump_rollback)

    # Subcommand: dump-package (Phần 6.1)
    parser_package = subparsers.add_parser(
        "dump-package",
        help="Tạo gói triển khai script PowerShell để bật/hoàn tác ghi dump trên đội máy",
    )
    parser_package.add_argument(
        "--out",
        required=True,
        help="Thư mục xuất gói triển khai (chứa Enable-CrashDump.ps1, Rollback-CrashDump.ps1, README)",
    )
    parser_package.set_defaults(func=cmd_dump_package)

    # Subcommand: dump-fleet (Phần 6.1)
    parser_fleet = subparsers.add_parser(
        "dump-fleet",
        help="Quét và tổng hợp báo cáo trạng thái sẵn sàng ghi dump của toàn bộ đội máy tính",
    )
    parser_fleet.add_argument(
        "--dir",
        required=True,
        help="Đường dẫn thư mục chia sẻ mạng chứa các file JSON báo cáo thu thập từ các máy trạm",
    )
    parser_fleet.add_argument(
        "--export",
        help="Đường dẫn xuất file Excel báo cáo tổng hợp đội máy (.xlsx)",
    )
    parser_fleet.set_defaults(func=cmd_dump_fleet)

    # Subcommand: selftest (Phần 6.1)
    parser_selftest = subparsers.add_parser(
        "selftest",
        help="Tự kiểm tra toàn diện phần mềm (CSDL, Quy tắc YAML, Collector dump_config)",
    )
    parser_selftest.set_defaults(func=cmd_selftest)

    # ==================== ĐỢT 05: TRIAGE READER SUBCOMMANDS ====================

    # Subcommand: triage-info
    parser_tinfo = subparsers.add_parser(
        "triage-info",
        help="Đọc cấu trúc minidump triage thuần Python (không cần WinDbg/cdb)",
    )
    parser_tinfo.add_argument("dump_path", help="Đường dẫn tới file minidump (.dmp)")
    parser_tinfo.add_argument("--json", action="store_true", help="Xuất kết quả dưới định dạng JSON")
    parser_tinfo.set_defaults(func=cmd_triage_info)

    # Subcommand: triage-compare
    parser_tcompare = subparsers.add_parser(
        "triage-compare",
        help="So sánh kết quả đọc triage nội bộ với WinDbg cdb.exe (nếu cdb có sẵn)",
    )
    parser_tcompare.add_argument("dump_path", help="Đường dẫn tới file minidump (.dmp)")
    parser_tcompare.set_defaults(func=cmd_triage_compare)

    return parser




def main(argv=None):
    """Điểm vào chính của ứng dụng dòng lệnh."""
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

