"""Giao diện & Theme cho PySide6 - DumpAnalyzer.

Cung cấp bảng màu hiện đại, độ tương phản cao, phong cách Slate/Charcoal chuyên nghiệp
dành cho kỹ thuật viên IT. Hỗ trợ các thẻ nhãn chữ kèm màu (badge) theo tiêu chuẩn chẩn đoán.
"""

from typing import Tuple

# Bảng màu chuẩn giao diện (Slate Dark Palette)
COLOR_BG_PRIMARY = "#0f172a"      # Nền chính (Slate 900)
COLOR_BG_SURFACE = "#1e293b"      # Thẻ card / Panel (Slate 800)
COLOR_BG_INPUT = "#334155"        # Ô nhập liệu / Ô bảng (Slate 700)
COLOR_TEXT_PRIMARY = "#f8fafc"    # Chữ chính trắng sáng (Slate 50)
COLOR_TEXT_MUTED = "#94a3b8"      # Chữ phụ / mô tả (Slate 400)
COLOR_BORDER = "#334155"          # Viền (Slate 700)
COLOR_BORDER_LIGHT = "#475569"    # Viền sáng hơn (Slate 600)

COLOR_ACCENT = "#3b82f6"          # Xanh dương điểm nhấn (Blue 500)
COLOR_ACCENT_HOVER = "#2563eb"    # Xanh dương hover (Blue 600)
COLOR_SUCCESS = "#22c55e"         # Xanh lá thành công (Green 500)
COLOR_WARNING = "#f59e0b"         # Vàng cam cảnh báo (Amber 500)
COLOR_DANGER = "#ef4444"          # Đỏ nguy hiểm (Red 500)
COLOR_PURPLE = "#a855f7"          # Tím nhấn (Purple 500)


def get_suspect_badge_color(suspect_type: str) -> Tuple[str, str]:
    """Trả về (màu nền, màu chữ) cho nhóm nghi ngờ."""
    s = suspect_type.lower()
    if "gpu" in s:
        return "#1e3a8a", "#93c5fd"   # Xanh dương đậm / xanh nhạt
    elif "ram" in s:
        return "#581c87", "#e9d5ff"   # Tím đậm / tím nhạt
    elif "cpu" in s:
        return "#7c2d12", "#fdba74"   # Cam đậm / cam nhạt
    elif "storage" in s or "ổ cứng" in s:
        return "#134e4a", "#99f6e4"   # Xanh mòng két / ngọc nhạt
    elif "psu" in s or "nguồn" in s:
        return "#78350f", "#fde68a"   # Vàng đất / vàng nhạt
    elif "thermal" in s or "nhiệt" in s:
        return "#7f1d1d", "#fca5a5"   # Đỏ sẫm / đỏ nhạt
    elif "driver" in s:
        return "#14532d", "#86efac"   # Xanh lá sẫm / xanh lá nhạt
    return "#334155", "#cbd5e1"       # Xám mặc định


def get_confidence_badge_style(confidence: str) -> str:
    """Trả về CSS cho huy hiệu độ tin cậy."""
    c = confidence.lower()
    if c == "cao":
        return "background-color: #14532d; color: #86efac; border: 1px solid #22c55e; font-weight: bold; padding: 4px 10px; border-radius: 6px;"
    elif c == "trung bình":
        return "background-color: #78350f; color: #fde68a; border: 1px solid #f59e0b; font-weight: bold; padding: 4px 10px; border-radius: 6px;"
    elif c == "thấp":
        return "background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; font-weight: bold; padding: 4px 10px; border-radius: 6px;"
    return "background-color: #334155; color: #94a3b8; border: 1px solid #64748b; font-weight: bold; padding: 4px 10px; border-radius: 6px;"


def get_method_badge_style(method: str) -> str:
    """Trả về CSS cho huy hiệu phương thức phân tích."""
    m = method.lower()
    if m == "log_only":
        return "background-color: #450a0a; color: #f87171; border: 1px solid #ef4444; font-weight: bold; padding: 3px 8px; border-radius: 4px;"
    elif m == "header_only":
        return "background-color: #064e3b; color: #6ee7b7; border: 1px solid #10b981; font-weight: bold; padding: 3px 8px; border-radius: 4px;"
    return "background-color: #1e3a8a; color: #93c5fd; border: 1px solid #3b82f6; font-weight: bold; padding: 3px 8px; border-radius: 4px;"


MAIN_STYLESHEET = f"""
QMainWindow {{
    background-color: {COLOR_BG_PRIMARY};
    color: {COLOR_TEXT_PRIMARY};
}}

QWidget {{
    background-color: {COLOR_BG_PRIMARY};
    color: {COLOR_TEXT_PRIMARY};
    font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}

/* Card Frame */
QFrame#CardFrame {{
    background-color: {COLOR_BG_SURFACE};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 16px;
}}

/* Toolbar & Header Controls */
QFrame#HeaderBar {{
    background-color: {COLOR_BG_SURFACE};
    border-bottom: 2px solid {COLOR_BORDER};
    padding: 14px 20px;
}}

QLabel#HeaderTitle {{
    font-size: 18px;
    font-weight: bold;
    color: {COLOR_TEXT_PRIMARY};
}}

QLabel#HeaderSubtitle {{
    font-size: 13px;
    color: {COLOR_TEXT_MUTED};
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background-color: {COLOR_BG_PRIMARY};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {COLOR_BG_SURFACE};
    color: {COLOR_TEXT_MUTED};
    padding: 10px 22px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
    font-size: 13px;
    border: 1px solid {COLOR_BORDER};
    border-bottom: none;
}}

QTabBar::tab:selected {{
    background-color: {COLOR_ACCENT};
    color: #ffffff;
    font-weight: bold;
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLOR_BG_INPUT};
    color: {COLOR_TEXT_PRIMARY};
}}

/* Buttons */
QPushButton {{
    background-color: {COLOR_BG_INPUT};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER_LIGHT};
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 600;
    min-height: 22px;
}}

QPushButton:hover {{
    background-color: {COLOR_BORDER_LIGHT};
}}

QPushButton:pressed {{
    background-color: {COLOR_BG_SURFACE};
}}

QPushButton#PrimaryButton {{
    background-color: {COLOR_ACCENT};
    color: #ffffff;
    border: 1px solid {COLOR_ACCENT_HOVER};
    font-weight: bold;
    font-size: 13px;
    padding: 9px 22px;
}}

QPushButton#PrimaryButton:hover {{
    background-color: {COLOR_ACCENT_HOVER};
}}

QPushButton#DangerButton {{
    background-color: {COLOR_DANGER};
    color: #ffffff;
    border: 1px solid #b91c1c;
    font-weight: bold;
}}

QPushButton#DangerButton:hover {{
    background-color: #dc2626;
}}

/* Input fields */
QLineEdit, QComboBox, QDateTimeEdit, QDateEdit, QSpinBox {{
    background-color: {COLOR_BG_INPUT};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER_LIGHT};
    border-radius: 6px;
    padding: 7px 12px;
    selection-background-color: {COLOR_ACCENT};
    min-height: 24px;
}}

QLineEdit:focus, QComboBox:focus, QDateTimeEdit:focus, QDateEdit:focus {{
    border: 1px solid {COLOR_ACCENT};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid {COLOR_BORDER_LIGHT};
}}

QComboBox QAbstractItemView {{
    background-color: {COLOR_BG_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER_LIGHT};
    selection-background-color: {COLOR_ACCENT};
}}

/* Table Widget */
QTableWidget {{
    background-color: {COLOR_BG_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    gridline-color: {COLOR_BORDER};
    selection-background-color: #1e3a8a;
    selection-color: #ffffff;
}}

QTableWidget::item {{
    padding: 9px 12px;
    border-bottom: 1px solid {COLOR_BORDER};
}}

QHeaderView::section {{
    background-color: #0b1120;
    color: {COLOR_TEXT_MUTED};
    font-weight: bold;
    font-size: 12px;
    text-transform: uppercase;
    padding: 10px 12px;
    border: none;
    border-right: 1px solid {COLOR_BORDER};
    border-bottom: 2px solid {COLOR_BORDER};
}}

/* Scrollbar */
QScrollBar:vertical {{
    background-color: {COLOR_BG_SURFACE};
    width: 10px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLOR_BORDER_LIGHT};
    min-height: 20px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLOR_ACCENT};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* Progress Bar */
QProgressBar {{
    background-color: {COLOR_BG_INPUT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
    height: 14px;
}}

QProgressBar::chunk {{
    background-color: {COLOR_ACCENT};
    border-radius: 5px;
}}

/* Text Edit */
QTextEdit, QPlainTextEdit {{
    background-color: #0b1120;
    color: #e2e8f0;
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    padding: 10px;
}}
"""
