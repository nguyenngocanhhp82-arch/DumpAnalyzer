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
)
from dumpanalyzer.analyzer.cdb_runner import (
    analyze_dump_file,
    warmup_symbols,
)
from dumpanalyzer.collectors.eventlog import read_system_events
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
    """Thu thập và hiển thị các sự kiện Event Log quan trọng, phát hiện crash log_only."""
    print_banner()
    print("\n--- THU THẬP & TƯƠNG QUAN SỰ KIỆN EVENT LOG (System Log) ---")

    db = Database()
    events = read_system_events(
        from_date=args.from_date,
        to_date=args.to_date,
        debug_ps=getattr(args, "debug_ps", False),
    )

    if not events:
        print("[!] Không tìm thấy sự kiện nghi vấn nào trong khoảng thời gian đã chọn (hoặc đang chạy trên Linux).")
        db.close()
        return 0

    print(f"[OK] Thu thập thành công {len(events)} sự kiện đáng chú ý.\n")

    # In bảng sự kiện
    col_t = 20
    col_prov = 32
    col_id = 8
    col_msg = 45

    line_h = f"{'Thời điểm (Giờ địa phương)':<{col_t}} | {'Nguồn (Provider)':<{col_prov}} | {'ID':<{col_id}} | {'Tóm tắt'}"
    sep = "-" * len(line_h) + "-" * 20
    print(sep)
    print(line_h)
    print(sep)
    for e in events:
        t_str = utc_to_local_str(e.get("time_created_utc"))[:col_t]
        p_str = e.get("provider", "")[:col_prov]
        id_str = str(e.get("event_id", 0))[:col_id]
        raw_m = e.get("raw_message", "")
        # Lấy dòng đầu tiên của message
        first_line = raw_m.strip().splitlines()[0] if raw_m else ""
        print(f"{t_str:<{col_t}} | {p_str:<{col_prov}} | {id_str:<{col_id}} | {first_line[:col_msg]}")
    print(sep)

    # Phát hiện crash không có dump
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
    detected_log_only = correlator.detect_log_only_crashes(existing_crashes, events)

    if detected_log_only:
        print(f"\n[!] PHÁT HIỆN {len(detected_log_only)} VỤ SẬP HỆ THỐNG KHÔNG CÓ DUMP (Chế độ log_only):")
        for crash_obj, matched_evs in detected_log_only:
            # Lưu vào DB nếu chưa có
            existing = db.get_crash_by_sha256(crash_obj.dump_sha256)
            if not existing:
                c_id = db.insert_crash(crash_obj)
            else:
                c_id = existing["id"]

            t_local = utc_to_local_str(crash_obj.crash_time_utc)
            code_str = crash_obj.bugcheck_code or "Không có BSOD (Tắt nguồn/treo cứng)"
            print(f"    * Lúc {t_local}: Mã lỗi = {code_str} | Tên: {crash_obj.bugcheck_name}")

            # Ghép và lưu evidence
            evidences = correlator.correlate_events_to_crash(crash_obj, events)
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


def build_parser() -> argparse.ArgumentParser:
    """Xây dựng bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        prog="dumpanalyzer",
        description="DumpAnalyzer - Phân tích BSOD dump kết hợp Windows Event Log",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"DumpAnalyzer v{__version__}",
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

