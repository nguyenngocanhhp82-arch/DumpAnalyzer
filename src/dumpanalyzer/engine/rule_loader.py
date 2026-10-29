"""
Module nạp và kiểm tra tính hợp lệ của các file quy tắc chẩn đoán (YAML Rule Loader).
Cung cấp khả năng kiểm tra cú pháp kèm số dòng/cột cụ thể khi file cấu hình bị lỗi.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

from dumpanalyzer.core.config import get_rules_dir, get_settings_path

logger = logging.getLogger("dumpanalyzer.engine.rule_loader")


class RuleLoadError(Exception):
    """Ngoại lệ khi file YAML bị lỗi cú pháp hoặc cấu trúc không hợp lệ."""
    def __init__(self, message: str, file_path: Optional[Path] = None, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.file_path = file_path
        self.line = line
        self.column = column

    def __str__(self) -> str:
        loc = ""
        if self.file_path:
            loc += f" [{self.file_path.name}]"
        if self.line is not None:
            loc += f" Dòng {self.line}"
        if self.column is not None:
            loc += f", Cột {self.column}"
        return f"{self.message}{loc}"


def normalize_bugcheck_code(code: Any) -> str:
    """
    Chuẩn hoá mã Bug Check về dạng chuỗi Hex viết hoa (ví dụ: '0x124', '0x1A', '0x0').
    Hỗ trợ cả đầu vào dạng int (do PyYAML tự parse số hex thành int) hoặc chuỗi.
    """
    if isinstance(code, int):
        return f"0x{code:X}"
    code_str = str(code).strip()
    try:
        val = int(code_str, 16) if code_str.lower().startswith("0x") else int(code_str, 16)
        return f"0x{val:X}"
    except ValueError:
        return code_str.upper()


def load_yaml_with_line_numbers(file_path: Path) -> Tuple[Optional[Any], Optional[str]]:
    """
    Đọc và parse một file YAML an toàn.
    Nếu có lỗi cú pháp, trả về chi tiết kèm số dòng và số cột chính xác.
    """
    if not file_path.exists():
        return None, f"File không tồn tại: {file_path}"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)
            return data, None
    except yaml.YAMLError as exc:
        line = getattr(exc, "problem_mark", None)
        if line:
            err_msg = (
                f"Lỗi cú pháp YAML trong file '{file_path.name}' "
                f"tại dòng {line.line + 1}, cột {line.column + 1}: {exc.problem}"
            )
        else:
            err_msg = f"Lỗi cú pháp YAML trong file '{file_path.name}': {exc}"
        return None, err_msg
    except Exception as exc:
        return None, f"Lỗi đọc file '{file_path.name}': {exc}"


def validate_bugcheck_rules(data: Any, file_path: Path) -> List[str]:
    """Kiểm tra tính hợp lệ của cấu trúc file bugcheck_rules.yaml."""
    errors = []
    if not isinstance(data, dict):
        return [f"'{file_path.name}': Nội dung gốc phải là một từ điển (dict) các mã Bug Check."]

    for raw_code, rule in data.items():
        code_str = normalize_bugcheck_code(raw_code)
        if not isinstance(rule, dict):
            errors.append(f"'{file_path.name}' mã {code_str}: Cấu hình phải là một từ điển.")
            continue
        if "name" not in rule:
            errors.append(f"'{file_path.name}' mã {code_str}: Thiếu trường bắt buộc 'name'.")
        if "suspects" not in rule or not isinstance(rule["suspects"], dict):
            errors.append(f"'{file_path.name}' mã {code_str}: Thiếu hoặc sai định dạng trường 'suspects'.")
        else:
            for s, weight in rule["suspects"].items():
                if not isinstance(weight, (int, float)):
                    errors.append(f"'{file_path.name}' mã {code_str}: Trọng số của '{s}' phải là số.")

    return errors


def validate_driver_map(data: Any, file_path: Path) -> List[str]:
    """Kiểm tra tính hợp lệ của cấu trúc file driver_map.yaml."""
    errors = []
    if not isinstance(data, dict):
        return [f"'{file_path.name}': Nội dung gốc phải là một từ điển."]

    drivers = data.get("drivers")
    if not isinstance(drivers, dict):
        errors.append(f"'{file_path.name}': Thiếu trường 'drivers' hoặc không phải từ điển.")
    else:
        for drv_name, info in drivers.items():
            if not isinstance(info, dict):
                errors.append(f"'{file_path.name}' driver '{drv_name}': Thông tin phải là từ điển.")
                continue
            for req in ("device", "type", "action"):
                if req not in info:
                    errors.append(f"'{file_path.name}' driver '{drv_name}': Thiếu trường bắt buộc '{req}'.")

    ms_core = data.get("ms_core_modules")
    if not isinstance(ms_core, list):
        errors.append(f"'{file_path.name}': Thiếu danh sách 'ms_core_modules'.")

    return errors


def validate_event_rules(data: Any, file_path: Path) -> List[str]:
    """Kiểm tra tính hợp lệ của cấu trúc file event_rules.yaml."""
    errors = []
    if not isinstance(data, dict):
        return [f"'{file_path.name}': Nội dung gốc phải là một từ điển."]

    events = data.get("events")
    if not isinstance(events, list):
        return [f"'{file_path.name}': Thiếu danh sách quy tắc 'events'."]

    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            errors.append(f"'{file_path.name}' sự kiện #{idx + 1}: Phải là một từ điển.")
            continue
        if "source" not in ev:
            errors.append(f"'{file_path.name}' sự kiện #{idx + 1}: Thiếu trường 'source'.")
        if "ids" not in ev or not isinstance(ev["ids"], list):
            errors.append(f"'{file_path.name}' sự kiện #{idx + 1}: Thiếu danh sách 'ids'.")
        if "adds" not in ev or not isinstance(ev["adds"], dict):
            errors.append(f"'{file_path.name}' sự kiện #{idx + 1}: Thiếu từ điển trọng số 'adds'.")

    return errors


def validate_patterns(data: Any, file_path: Path) -> List[str]:
    """Kiểm tra tính hợp lệ của cấu trúc file patterns.yaml."""
    errors = []
    if not isinstance(data, dict):
        return [f"'{file_path.name}': Nội dung gốc phải là một từ điển."]

    patterns = data.get("patterns")
    if not isinstance(patterns, list):
        return [f"'{file_path.name}': Thiếu danh sách mẫu hình 'patterns'."]

    for idx, pat in enumerate(patterns):
        if not isinstance(pat, dict):
            errors.append(f"'{file_path.name}' mẫu hình #{idx + 1}: Phải là một từ điển.")
            continue
        if "name" not in pat:
            errors.append(f"'{file_path.name}' mẫu hình #{idx + 1}: Thiếu trường 'name'.")
        if "when" not in pat or not isinstance(pat["when"], dict):
            errors.append(f"'{file_path.name}' mẫu hình #{idx + 1}: Thiếu điều kiện 'when'.")
        if "add" not in pat or not isinstance(pat["add"], dict):
            errors.append(f"'{file_path.name}' mẫu hình #{idx + 1}: Thiếu điểm cộng 'add'.")

    return errors


def validate_settings(data: Any, file_path: Path) -> List[str]:
    """Kiểm tra tính hợp lệ của cấu trúc file settings.yaml."""
    errors = []
    if not isinstance(data, dict):
        return [f"'{file_path.name}': Nội dung gốc phải là một từ điển."]

    conf_thresh = data.get("confidence_thresholds")
    if not isinstance(conf_thresh, dict) or "high" not in conf_thresh or "medium" not in conf_thresh:
        errors.append(f"'{file_path.name}': Thiếu hoặc sai định dạng 'confidence_thresholds' (cần có high, medium).")

    for num_key in ("min_verdict_score", "conflict_threshold", "repeat_multiplier"):
        if num_key not in data or not isinstance(data[num_key], (int, float)):
            errors.append(f"'{file_path.name}': Thiếu hoặc sai kiểu dữ liệu trường '{num_key}'.")

    return errors


def validate_rules_and_settings(config_dir: Optional[Path] = None) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Kiểm tra toàn diện tất cả các file cấu hình và quy tắc trong thư mục config.
    Trả về: (is_valid, list_of_errors, loaded_summary_dict).
    """
    all_errors = []
    summary = {}

    rules_path = config_dir / "rules" if config_dir else get_rules_dir()
    settings_file = config_dir / "settings.yaml" if config_dir else get_settings_path()

    # 1. Kiểm tra settings.yaml
    s_data, s_err = load_yaml_with_line_numbers(settings_file)
    if s_err:
        all_errors.append(s_err)
    elif s_data:
        val_errs = validate_settings(s_data, settings_file)
        all_errors.extend(val_errs)
        summary["settings"] = True

    # 2. Kiểm tra bugcheck_rules.yaml
    bc_file = rules_path / "bugcheck_rules.yaml"
    bc_data, bc_err = load_yaml_with_line_numbers(bc_file)
    if bc_err:
        all_errors.append(bc_err)
    elif bc_data:
        val_errs = validate_bugcheck_rules(bc_data, bc_file)
        all_errors.extend(val_errs)
        summary["bugcheck_rules_count"] = len(bc_data)

    # 3. Kiểm tra driver_map.yaml
    dm_file = rules_path / "driver_map.yaml"
    dm_data, dm_err = load_yaml_with_line_numbers(dm_file)
    if dm_err:
        all_errors.append(dm_err)
    elif dm_data:
        val_errs = validate_driver_map(dm_data, dm_file)
        all_errors.extend(val_errs)
        summary["driver_mappings_count"] = len(dm_data.get("drivers", {}))
        summary["ms_core_modules_count"] = len(dm_data.get("ms_core_modules", []))

    # 4. Kiểm tra event_rules.yaml
    ev_file = rules_path / "event_rules.yaml"
    ev_data, ev_err = load_yaml_with_line_numbers(ev_file)
    if ev_err:
        all_errors.append(ev_err)
    elif ev_data:
        val_errs = validate_event_rules(ev_data, ev_file)
        all_errors.extend(val_errs)
        summary["event_rules_count"] = len(ev_data.get("events", []))

    # 5. Kiểm tra patterns.yaml
    pt_file = rules_path / "patterns.yaml"
    pt_data, pt_err = load_yaml_with_line_numbers(pt_file)
    if pt_err:
        all_errors.append(pt_err)
    elif pt_data:
        val_errs = validate_patterns(pt_data, pt_file)
        all_errors.extend(val_errs)
        summary["patterns_count"] = len(pt_data.get("patterns", []))

    is_valid = len(all_errors) == 0
    return is_valid, all_errors, summary


def load_all_rules(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Nạp và chuẩn hoá toàn bộ các quy tắc sẵn sàng cho Scorer và Verdict Engine sử dụng.
    Chuẩn hoá toàn bộ mã Bug Check thành dạng chuỗi '0x...' viết hoa để tra cứu tức thì O(1).
    """
    rules_path = config_dir / "rules" if config_dir else get_rules_dir()

    # Nạp bugcheck_rules
    bc_file = rules_path / "bugcheck_rules.yaml"
    bc_raw, err = load_yaml_with_line_numbers(bc_file)
    if err:
        logger.error(err)
        bc_raw = {}
    normalized_bc = {}
    if isinstance(bc_raw, dict):
        for k, v in bc_raw.items():
            normalized_bc[normalize_bugcheck_code(k)] = v

    # Nạp driver_map
    dm_file = rules_path / "driver_map.yaml"
    dm_raw, err = load_yaml_with_line_numbers(dm_file)
    if err:
        logger.error(err)
        dm_raw = {}
    drivers = dm_raw.get("drivers", {}) if isinstance(dm_raw, dict) else {}
    ms_core = [m.lower() for m in dm_raw.get("ms_core_modules", [])] if isinstance(dm_raw, dict) else []

    # Nạp event_rules
    ev_file = rules_path / "event_rules.yaml"
    ev_raw, err = load_yaml_with_line_numbers(ev_file)
    if err:
        logger.error(err)
        ev_raw = {}
    events = ev_raw.get("events", []) if isinstance(ev_raw, dict) else []

    # Nạp patterns
    pt_file = rules_path / "patterns.yaml"
    pt_raw, err = load_yaml_with_line_numbers(pt_file)
    if err:
        logger.error(err)
        pt_raw = {}
    patterns = pt_raw.get("patterns", []) if isinstance(pt_raw, dict) else []

    return {
        "bugchecks": normalized_bc,
        "drivers": drivers,
        "ms_core_modules": ms_core,
        "event_rules": events,
        "patterns": patterns,
    }
