"""
Module điều phối chạy ngầm cdb.exe (Windows Debugging Tools).
Đảm bảo:
- Sử dụng danh sách tham số an toàn trong subprocess (không dùng chuỗi shell).
- Kiểm soát timeout chặt chẽ (mặc định 300 giây).
- Hỗ trợ chạy đa luồng song song có giới hạn (2 - 4 tiến trình).
- Fallback về header_only an toàn nếu thiếu cdb hoặc lỗi phân tích.
- Bổ sung các lệnh chuyên sâu theo từng mã Bug Check (extra_cdb).
"""

import subprocess
import concurrent.futures
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Union
import yaml

from dumpanalyzer.core.config import (
    load_settings,
    find_cdb_executable,
    get_project_root,
)
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.analyzer.cdb_parser import CdbParser, CdbAnalysisResult
from dumpanalyzer.analyzer.header_parser import parse_dump_header

logger = get_logger("cdb_runner")


@dataclass
class CdbExecutionResult:
    """Kết quả thực thi tiến trình cdb.exe."""
    success: bool = False
    raw_output: str = ""
    timeout: bool = False
    return_code: int = -1
    error_message: str = ""
    fallback_header: bool = False


def get_extra_cdb_commands(bugcheck_code: str, params: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Lấy danh sách các lệnh cdb mở rộng theo mã Bug Check từ file rules/bugcheck_rules.yaml.
    Ví dụ: 0x124 -> !errrec {p2}; 0x133 -> !dpcs, !timer
    """
    rules_path = get_project_root() / "config" / "rules" / "bugcheck_rules.yaml"
    extra_cmds: List[str] = []

    if not rules_path.exists():
        return extra_cmds

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            rules = yaml.safe_load(f)
            if not isinstance(rules, dict):
                return extra_cmds

        # Tra mã dạng hex
        entry = rules.get(bugcheck_code)
        if not entry and bugcheck_code.startswith("0x"):
            # Thử bỏ 0x hoặc đổi dạng int
            try:
                val = int(bugcheck_code, 16)
                entry = rules.get(f"0x{val:X}") or rules.get(val)
            except ValueError:
                pass

        if entry and isinstance(entry, dict) and "extra_cdb" in entry:
            raw_list = entry["extra_cdb"]
            if isinstance(raw_list, list):
                for cmd in raw_list:
                    cmd_str = str(cmd)
                    if params:
                        for k, v in params.items():
                            cmd_str = cmd_str.replace(f"{{{k.lower()}}}", str(v))
                    extra_cmds.append(cmd_str)
    except Exception as e:
        logger.warning(f"Lỗi khi đọc extra_cdb từ rules: {e}")

    return extra_cmds


def build_cdb_command_args(
    dump_path: Union[str, Path],
    cdb_exe: str,
    symbol_path: str,
    extra_commands: Optional[List[str]] = None,
    logo_file: Optional[Union[str, Path]] = None,
) -> List[str]:
    """Xây dựng danh sách tham số dòng lệnh an toàn cho cdb.exe."""
    base_script = ["!analyze -v", ".bugcheck", "vertarget", ".time", "kv", "lm t n"]
    if extra_commands:
        base_script.extend(extra_commands)
    base_script.append("q")  # Luôn kết thúc bằng lệnh thoát quit

    script_cmd = "; ".join(base_script)

    args = [
        str(cdb_exe),
        "-z", str(dump_path),
        "-y", str(symbol_path),
        "-c", script_cmd,
    ]

    if logo_file:
        args.extend(["-logo", str(logo_file)])

    return args


def execute_cdb(
    dump_path: Union[str, Path],
    cdb_path: Optional[str] = None,
    symbol_path: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    extra_commands: Optional[List[str]] = None,
) -> CdbExecutionResult:
    """
    Chạy cdb.exe để phân tích một file dump với cơ chế timeout an toàn.
    """
    settings = load_settings()
    cdb_exe = find_cdb_executable(cdb_path or settings.get("cdb_path"))

    if not cdb_exe:
        return CdbExecutionResult(
            success=False,
            error_message="Không tìm thấy cdb.exe (Windows Debugging Tools).",
            fallback_header=True,
        )

    sym_path = symbol_path or settings.get("symbol_path", "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols")
    timeout = timeout_seconds or settings.get("cdb_timeout_seconds", 300)

    dump_path_obj = Path(dump_path).resolve()
    if not dump_path_obj.exists():
        return CdbExecutionResult(
            success=False,
            error_message=f"File dump không tồn tại: {dump_path}",
        )

    cmd_args = build_cdb_command_args(
        dump_path=dump_path_obj,
        cdb_exe=cdb_exe,
        symbol_path=sym_path,
        extra_commands=extra_commands,
    )

    logger.info(f"Đang chạy cdb trên {dump_path_obj.name} (timeout: {timeout}s)...")
    try:
        proc = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return CdbExecutionResult(
            success=True,
            raw_output=proc.stdout or "",
            return_code=proc.returncode,
        )
    except subprocess.TimeoutExpired as e:
        logger.warning(f"cdb phân tích {dump_path_obj.name} bị quá thời gian ({timeout}s).")
        partial_output = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode("utf-8", errors="replace") if e.stdout else "")
        return CdbExecutionResult(
            success=False,
            raw_output=partial_output,
            timeout=True,
            error_message=f"Phân tích cdb bị quá thời gian ({timeout} giây)",
            fallback_header=True,
        )
    except Exception as e:
        logger.error(f"Lỗi khi thực thi cdb: {e}")
        return CdbExecutionResult(
            success=False,
            error_message=str(e),
            fallback_header=True,
        )


def analyze_dump_file(
    dump_path: Union[str, Path],
    cdb_path: Optional[str] = None,
    symbol_path: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Quy trình phân tích toàn diện 1 file dump:
    1. Đọc nhanh header để lấy BugCheckCode và 4 tham số.
    2. Lấy extra_cdb phù hợp với mã lỗi.
    3. Chạy cdb.exe ngầm có timeout.
    4. Nếu cdb thành công: phân tích output bằng CdbParser.
    5. Nếu cdb thiếu/lỗi/timeout: fallback về header_only.
    """
    path_obj = Path(dump_path).resolve()

    # Bước 1: Đọc nhanh header
    header_info = parse_dump_header(path_obj)

    params_dict = {
        "p1": header_info.p1,
        "p2": header_info.p2,
        "p3": header_info.p3,
        "p4": header_info.p4,
    }
    extra_cmds = get_extra_cdb_commands(header_info.bugcheck_code, params_dict)

    # Bước 2: Chạy cdb
    exec_res = execute_cdb(
        dump_path=path_obj,
        cdb_path=cdb_path,
        symbol_path=symbol_path,
        timeout_seconds=timeout_seconds,
        extra_commands=extra_cmds,
    )

    parser = CdbParser()

    if exec_res.success and exec_res.raw_output:
        cdb_result = parser.parse(exec_res.raw_output)

        # Nếu cdb không bóc tách được mã lỗi (do symbol thiếu), dùng mã lỗi từ header
        if not cdb_result.bugcheck_code or cdb_result.bugcheck_code == "0x0":
            if header_info.valid and header_info.bugcheck_code:
                cdb_result.bugcheck_code = header_info.bugcheck_code
                cdb_result.bugcheck_name = header_info.bugcheck_name

        return {
            "analyzed_by": "cdb",
            "cdb_result": cdb_result,
            "raw_output": exec_res.raw_output,
            "header_info": header_info,
            "error": None,
        }
    else:
        # Fallback về header_only
        logger.info(f"Fallback về header_only cho file {path_obj.name}: {exec_res.error_message}")
        fallback_res = CdbAnalysisResult(
            bugcheck_code=header_info.bugcheck_code,
            bugcheck_name=header_info.bugcheck_name,
            p1=header_info.p1,
            p2=header_info.p2,
            p3=header_info.p3,
            p4=header_info.p4,
            crash_time_utc=header_info.crash_time_utc,
            raw_output=exec_res.raw_output,
        )
        return {
            "analyzed_by": "header_only",
            "cdb_result": fallback_res,
            "raw_output": exec_res.raw_output,
            "header_info": header_info,
            "error": exec_res.error_message,
        }


def analyze_dumps_parallel(
    dump_paths: List[Union[str, Path]],
    max_workers: int = 2,
    cdb_path: Optional[str] = None,
    symbol_path: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Phân tích nhiều file dump song song bằng ThreadPoolExecutor.
    Giới hạn số tiến trình song song (mặc định 2) để tránh quá tải CPU/Disk.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(
                analyze_dump_file,
                p,
                cdb_path,
                symbol_path,
                timeout_seconds,
            ): p
            for p in dump_paths
        }
        for future in concurrent.futures.as_completed(future_to_path):
            p = future_to_path[future]
            try:
                res = future.result()
                results.append({"path": p, "result": res})
            except Exception as e:
                logger.error(f"Lỗi khi phân tích {p}: {e}")
                results.append({"path": p, "error": str(e)})

    return results


def warmup_symbols(cdb_path: Optional[str] = None, symbol_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Tải trước Symbol Microsoft để tránh bị treo/chậm khi phân tích hàng loạt.
    Kiểm tra thư mục lưu tạm symbol và thực hiện tải thử nghiệm symbol cơ bản.
    """
    settings = load_settings()
    cdb_exe = find_cdb_executable(cdb_path or settings.get("cdb_path"))
    sym_path = symbol_path or settings.get("symbol_path", "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols")

    if not cdb_exe:
        return {
            "success": False,
            "message": "Không tìm thấy cdb.exe để khởi động tải symbol.",
        }

    # Bóc tách đường dẫn cache cục bộ từ chuỗi srv*C:\Symbols*https:...
    parts = sym_path.split("*")
    cache_dir = parts[1] if len(parts) >= 2 else "C:\\Symbols"

    try:
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.debug(f"Không thể tạo thư mục symbol {cache_dir}: {e}")

    logger.info(f"Đang kiểm tra kết nối symbol server: {sym_path}")

    # Chạy cdb để tải thử symbol cho tiến trình hiện tại
    try:
        proc = subprocess.run(
            [cdb_exe, "-y", sym_path, "-c", ".reload; q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "success": True,
            "message": f"Máy chủ Symbol và thư mục lưu đệm '{cache_dir}' đã sẵn sàng.",
            "cache_dir": cache_dir,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Kết nối máy chủ Symbol Microsoft bị quá thời gian (Timeout). Hãy kiểm tra kết nối mạng.",
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Lỗi khi khởi động tải Symbol: {e}",
        }


def build_crash_from_dump(
    dump_path: Union[str, Path],
    settings: Optional[Dict[str, Any]] = None,
    machine_id: Optional[int] = None,
    sha256: Optional[str] = None,
) -> Any:
    """Phân tích dump file và trả về đối tượng Crash hoàn chỉnh."""
    from dumpanalyzer.core.models import Crash
    from dumpanalyzer.collectors.dump_finder import calculate_sha256

    path_obj = Path(dump_path).resolve()
    settings = settings or {}

    cdb_p = settings.get("cdb_path")
    sym_p = settings.get("symbol_path")
    timeout_s = settings.get("cdb_timeout_seconds", 300)

    res = analyze_dump_file(
        dump_path=path_obj,
        cdb_path=cdb_p,
        symbol_path=sym_p,
        timeout_seconds=timeout_s,
    )

    cdb_res = res["cdb_result"]
    h_info = res.get("header_info")
    analyzed_by = res.get("analyzed_by", "header_only")

    calculated_sha = sha256 or (calculate_sha256(path_obj) if path_obj.exists() else None)

    crash_time_utc = getattr(cdb_res, "crash_time_utc", None) or (getattr(h_info, "crash_time_utc", None) if h_info else None)
    if getattr(cdb_res, "crash_time_utc", None):
        crash_time_source = "cdb"
    elif h_info:
        crash_time_source = getattr(h_info, "crash_time_source", "header")
    else:
        crash_time_source = "unknown"

    return Crash(
        machine_id=machine_id,
        dump_path=str(path_obj),
        dump_sha256=calculated_sha,
        dump_type=getattr(h_info, "dump_type", "unknown") if h_info else "unknown",
        crash_time_utc=crash_time_utc,
        crash_time_source=crash_time_source,
        bugcheck_code=getattr(cdb_res, "bugcheck_code", None) or (getattr(h_info, "bugcheck_code", "0x0") if h_info else "0x0"),
        bugcheck_name=getattr(cdb_res, "bugcheck_name", None) or (getattr(h_info, "bugcheck_name", "UNKNOWN") if h_info else "UNKNOWN"),
        p1=getattr(cdb_res, "p1", None) or (getattr(h_info, "p1", "0x0") if h_info else "0x0"),
        p2=getattr(cdb_res, "p2", None) or (getattr(h_info, "p2", "0x0") if h_info else "0x0"),
        p3=getattr(cdb_res, "p3", None) or (getattr(h_info, "p3", "0x0") if h_info else "0x0"),
        p4=getattr(cdb_res, "p4", None) or (getattr(h_info, "p4", "0x0") if h_info else "0x0"),
        image_name=getattr(cdb_res, "image_name", "") or "",
        module_name=getattr(cdb_res, "module_name", "") or "",
        process_name=getattr(cdb_res, "process_name", "") or "",
        failure_bucket_id=getattr(cdb_res, "failure_bucket_id", "") or "",
        uptime_seconds=getattr(cdb_res, "uptime_seconds", None) or getattr(h_info, "uptime_seconds", 0) or 0,
        cdb_raw_output=res.get("raw_output"),
        analyzed_by=analyzed_by,
        suspect_driver=getattr(cdb_res, "suspect_driver", "") or "",
    )


