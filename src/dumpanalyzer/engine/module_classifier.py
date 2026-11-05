"""
Module phân loại danh tính và vai trò của các driver/module trong hệ thống (Đợt 05).
Tuân thủ N6: Không bao giờ quy chụp một driver là thủ phạm chỉ vì tên nó có trong module/stack.
Module không thuộc lớp nào là "chưa phân loại" (unclassified).
"""

from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml

from dumpanalyzer.core.config import get_rules_dir
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("module_classifier")

_CACHE_CLASSES: Optional[Dict[str, Set[str]]] = None


def load_module_classes(rules_dir: Optional[Path] = None, force_reload: bool = False) -> Dict[str, Set[str]]:
    """
    Tải danh sách các lớp module từ module_classes.yaml.
    Gộp ms_core_modules từ driver_map.yaml vào ms_inbox để tương thích ngược.
    """
    global _CACHE_CLASSES
    if _CACHE_CLASSES is not None and not force_reload:
        return _CACHE_CLASSES

    r_dir = rules_dir or get_rules_dir()
    classes_file = r_dir / "module_classes.yaml"
    result: Dict[str, Set[str]] = {
        "ms_inbox": set(),
        "fs_stack": set(),
        "usb_storage_driver": set(),
        "third_party_filter_known": set(),
    }

    if classes_file.exists():
        try:
            with open(classes_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                raw_classes = data.get("classes", {})
                for k, v in raw_classes.items():
                    if isinstance(v, list):
                        result[k] = {str(item).strip().lower() for item in v if item}
        except Exception as e:
            logger.warning(f"Lỗi nạp module_classes.yaml: {e}")

    # Gộp ms_core_modules từ driver_map.yaml vào ms_inbox
    driver_map_file = r_dir / "driver_map.yaml"
    if driver_map_file.exists():
        try:
            with open(driver_map_file, "r", encoding="utf-8") as f:
                d_data = yaml.safe_load(f) or {}
                ms_core = d_data.get("ms_core_modules", [])
                if isinstance(ms_core, list):
                    for item in ms_core:
                        if item:
                            result["ms_inbox"].add(str(item).strip().lower())
        except Exception as e:
            logger.warning(f"Lỗi nạp driver_map.yaml bổ sung: {e}")

    _CACHE_CLASSES = result
    return result


def _clean_name(name: str) -> str:
    """Chuẩn hóa tên module về chữ thường, bỏ khoảng trắng."""
    if not name:
        return ""
    # Cắt bỏ đuôi đường dẫn nếu có (ví dụ C:\\Windows\\System32\\drivers\\fastfat.sys -> fastfat.sys)
    base = name.split("\\")[-1].split("/")[-1].strip().lower()
    return base


def match_module_name(name: str, target: str) -> bool:
    """
    So khớp hai tên module (không phân biệt hoa thường).
    Hỗ trợ khớp prefix nếu tên bị cắt ngắn tối đa 12 ký tự (unloaded drivers).
    """
    c_name = _clean_name(name)
    c_target = _clean_name(target)
    if not c_name or not c_target:
        return False
    if c_name == c_target:
        return True
    # Nếu tên ngắn hơn và có độ dài <= 12 ký tự (giới hạn unloaded), kiểm tra prefix
    if len(c_name) <= 12 and c_target.startswith(c_name):
        return True
    if len(c_target) <= 12 and c_name.startswith(c_target):
        return True
    return False


def classify_module(name: str, rules_dir: Optional[Path] = None) -> List[str]:
    """Trả về danh sách các lớp mà module này thuộc về."""
    classes = load_module_classes(rules_dir=rules_dir)
    c_name = _clean_name(name)
    if not c_name:
        return []

    matched = []
    for cls_name, cls_set in classes.items():
        for item in cls_set:
            if match_module_name(c_name, item):
                matched.append(cls_name)
                break
    return matched


def is_ms_inbox(name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem module có phải là module Windows tiêu chuẩn (không phải bên thứ ba)."""
    return "ms_inbox" in classify_module(name, rules_dir=rules_dir)


def is_fs_stack(name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem module có nằm trên đường xử lý file hệ thống (fs_stack)."""
    return "fs_stack" in classify_module(name, rules_dir=rules_dir)


def is_usb_storage_driver(name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem module có phải driver lưu trữ USB (usbstor, uaspstor)."""
    return "usb_storage_driver" in classify_module(name, rules_dir=rules_dir)


def is_third_party_filter(name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem module có phải driver lọc của bên thứ ba đã biết."""
    return "third_party_filter_known" in classify_module(name, rules_dir=rules_dir)


def names_have_class(names: List[str], class_name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem trong danh sách tên module có ít nhất một module thuộc lớp class_name."""
    classes = load_module_classes(rules_dir=rules_dir)
    cls_set = classes.get(class_name, set())
    if not cls_set:
        return False

    for n in names:
        c_n = _clean_name(n)
        for target in cls_set:
            if match_module_name(c_n, target):
                return True
    return False


def names_have_class_not(names: List[str], class_name: str, rules_dir: Optional[Path] = None) -> bool:
    """Kiểm tra xem trong danh sách KHÔNG có module nào thuộc lớp class_name."""
    return not names_have_class(names, class_name, rules_dir=rules_dir)
