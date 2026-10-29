"""
Quản lý kết nối và thao tác với Cơ sở dữ liệu SQLite cho DumpAnalyzer.
Đảm bảo lưu trữ bền vững các vụ sập, bằng chứng và kết luận chẩn đoán.
"""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dumpanalyzer.core.config import get_project_root
from dumpanalyzer.core.models import MachineInfo, Crash, Evidence, Finding


def get_default_db_path() -> Path:
    """Trả về đường dẫn file SQLite mặc định trong thư mục data/."""
    db_dir = get_project_root() / "data"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "dumpanalyzer.db"


class Database:
    """Lớp điều phối kết nối và truy vấn CSDL SQLite."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if db_path is None:
            self.db_path = get_default_db_path()
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON;")
        return self.conn

    def _init_db(self) -> None:
        """Tạo các bảng CSDL từ schema.sql nếu chưa tồn tại."""
        schema_file = Path(__file__).resolve().parent / "schema.sql"
        if not schema_file.exists():
            raise FileNotFoundError(f"Không tìm thấy file schema SQL tại {schema_file}")

        with open(schema_file, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        conn = self._get_connection()
        with conn:
            conn.executescript(schema_sql)

    def close(self) -> None:
        """Đóng kết nối CSDL."""
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_crash_by_sha256(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        """Tra cứu vụ sập theo mã băm SHA256 (kiểm tra cache)."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM crash WHERE dump_sha256 = ?", (sha256_hash,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def insert_crash(self, crash: Crash) -> int:
        """Thêm mới một bản ghi Crash và trả về id vừa sinh."""
        conn = self._get_connection()
        sql = """
        INSERT INTO crash (
            machine_id, dump_path, dump_sha256, dump_type, crash_time_utc,
            bugcheck_code, bugcheck_name, p1, p2, p3, p4,
            image_name, module_name, process_name, failure_bucket_id,
            uptime_seconds, cdb_raw_output, analyzed_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            crash.machine_id,
            crash.dump_path,
            crash.dump_sha256,
            crash.dump_type,
            crash.crash_time_utc,
            crash.bugcheck_code,
            crash.bugcheck_name,
            crash.p1,
            crash.p2,
            crash.p3,
            crash.p4,
            crash.image_name,
            crash.module_name,
            crash.process_name,
            crash.failure_bucket_id,
            crash.uptime_seconds,
            crash.cdb_raw_output,
            crash.analyzed_by,
        )
        with conn:
            cursor = conn.execute(sql, params)
            crash_id = cursor.lastrowid
            crash.id = crash_id
            return crash_id

    def list_crashes(self) -> List[Dict[str, Any]]:
        """Lấy danh sách tất cả các vụ sập đã lưu."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM crash ORDER BY crash_time_utc DESC")
        return [dict(r) for r in cursor.fetchall()]
