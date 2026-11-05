"""Kiểm thử bộ phân loại module hệ thống (engine/module_classifier.py)."""

from dumpanalyzer.engine.module_classifier import (
    classify_module,
    is_ms_inbox,
    is_usb_storage_driver,
    names_have_class,
)


def test_classify_module_fastfat():
    """Kiểm tra fastfat.SYS thuộc ms_inbox và fs_stack."""
    classes = classify_module("fastfat.SYS")
    assert "ms_inbox" in classes
    assert "fs_stack" in classes
    assert is_ms_inbox("fastfat.SYS") is True


def test_classify_module_usbstor():
    """Kiểm tra USBSTOR.SYS là usb_storage_driver và ms_inbox."""
    assert is_usb_storage_driver("USBSTOR.SYS") is True
    assert is_usb_storage_driver("usbstor.sys") is True
    assert is_ms_inbox("usbstor.sys") is True


def test_usbxhci_not_usb_storage():
    """Kiểm tra usbxhci.sys (USB Host Controller) không bị phân loại nhầm là USB mass storage."""
    assert is_usb_storage_driver("usbxhci.sys") is False
    assert is_ms_inbox("usbxhci.sys") is True


def test_case_insensitivity():
    """Kiểm tra không phân biệt chữ hoa thường khi so khớp tên module."""
    assert is_ms_inbox("NTOSKRNL.EXE") is True
    assert is_ms_inbox("ntoskrnl.exe") is True
    assert is_ms_inbox("FltMgr.Sys") is True
    assert is_ms_inbox("FLTMGR.SYS") is True


def test_third_party_driver():
    """Kiểm tra driver bên thứ ba (như nvlddmkm.sys hoặc rt640x64.sys) không phải ms_inbox."""
    assert is_ms_inbox("nvlddmkm.sys") is False
    assert is_ms_inbox("rt640x64.sys") is False
    assert is_usb_storage_driver("nvlddmkm.sys") is False


def test_names_have_class():
    """Kiểm tra hàm kiểm tra tập hợp tên danh sách module."""
    mods = ["fltmgr.sys", "fastfat.SYS", "ntoskrnl.exe"]
    assert names_have_class(mods, "fs_stack") is True
    assert names_have_class(mods, "usb_storage_driver") is False

    mods_with_usb = ["fltmgr.sys", "USBSTOR.SYS", "ntoskrnl.exe"]
    assert names_have_class(mods_with_usb, "usb_storage_driver") is True
