"""
Cấu hình hệ thống ghi log xoay vòng (Rotating File Logging) cho DumpAnalyzer.
Hỗ trợ nhân viên IT theo dõi và chẩn đoán lỗi trong quá trình chạy.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Dict, Any
from dumpanalyzer.core.config import get_project_root, load_settings


def setup_logging(config: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Khởi tạo hệ thống logging:
    - Ghi ra console: thông báo ngắn gọn.
    - Ghi ra file xoay vòng: chi tiết kèm thời gian, module, dòng code.
    """
    if config is None:
        settings = load_settings()
        config = settings.get("logging", {})

    level_name = config.get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    log_file_rel = config.get("log_file", "./logs/dumpanalyzer.log")
    log_file_path = get_project_root() / Path(log_file_rel)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    max_bytes = config.get("max_bytes", 10 * 1024 * 1024)
    backup_count = config.get("backup_count", 5)

    logger = logging.getLogger("dumpanalyzer")
    logger.setLevel(level)

    # Tránh gắn handler nhiều lần nếu hàm được gọi lại
    if not logger.handlers:
        # File handler (xoay vòng)
        file_handler = RotatingFileHandler(
            str(log_file_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s:%(filename)s:%(lineno)d]: %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            "[%(levelname)s] %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Lấy logger con theo tên module."""
    if name:
        return logging.getLogger(f"dumpanalyzer.{name}")
    return logging.getLogger("dumpanalyzer")
