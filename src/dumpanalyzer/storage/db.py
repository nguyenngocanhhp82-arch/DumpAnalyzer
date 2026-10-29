"""
Quản lý kết nối và thao tác với Cơ sở dữ liệu SQLite cho DumpAnalyzer.
Đảm bảo lưu trữ bền vững các vụ sập, bằng chứng và kết luận chẩn đoán.
"""

import json
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

    def get_unprocessed_crashes(self) -> List[Dict[str, Any]]:
        """Lấy danh sách các crash chưa được phân tích sâu bằng cdb (analyzed_by != 'cdb')."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM crash WHERE analyzed_by != 'cdb' AND dump_type != 'none' ORDER BY crash_time_utc DESC"
        )
        return [dict(r) for r in cursor.fetchall()]

    def update_crash_cdb_results(
        self,
        crash_id: int,
        image_name: str,
        module_name: str,
        process_name: str,
        failure_bucket_id: str,
        uptime_seconds: int,
        cdb_raw_output: str,
        analyzed_by: str = "cdb",
    ) -> bool:
        """Cập nhật thông tin chi tiết và output thô từ cdb vào bản ghi crash."""
        conn = self._get_connection()
        sql = """
        UPDATE crash
        SET image_name = ?,
            module_name = ?,
            process_name = ?,
            failure_bucket_id = ?,
            uptime_seconds = ?,
            cdb_raw_output = ?,
            analyzed_by = ?
        WHERE id = ?
        """
        with conn:
            cursor = conn.execute(
                sql,
                (
                    image_name,
                    module_name,
                    process_name,
                    failure_bucket_id,
                    uptime_seconds,
                    cdb_raw_output,
                    analyzed_by,
                    crash_id,
                ),
            )
            return cursor.rowcount > 0

    def insert_machine(self, machine: MachineInfo) -> int:
        """Lưu hoặc cập nhật thông tin máy tính."""
        conn = self._get_connection()
        sql = """
        INSERT INTO machine (hostname, model, bios, cpu, os_build)
        VALUES (?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(
                sql, (machine.hostname, machine.model, machine.bios, machine.cpu, machine.os_build)
            )
            machine.id = cursor.lastrowid
            return machine.id

    def insert_evidence(self, ev: Evidence) -> int:
        """Lưu một bằng chứng liên quan đến crash."""
        conn = self._get_connection()
        sql = """
        INSERT INTO evidence (crash_id, kind, source, event_id, time_utc, summary, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(
                sql,
                (ev.crash_id, ev.kind, ev.source, ev.event_id, ev.time_utc, ev.summary, ev.detail),
            )
            ev.id = cursor.lastrowid
            return ev.id

    def get_evidences_by_crash(self, crash_id: int) -> List[Dict[str, Any]]:
        """Lấy danh sách tất cả các bằng chứng gắn với một vụ sập."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM evidence WHERE crash_id = ? ORDER BY time_utc ASC",
            (crash_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_crash_by_id(self, crash_id: int) -> Optional[Dict[str, Any]]:
        """Lấy thông tin chi tiết vụ sập theo ID."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM crash WHERE id = ?", (crash_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_machine_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Tìm thông tin máy theo hostname."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM machine WHERE hostname = ? ORDER BY id DESC LIMIT 1", (hostname,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_crashes_by_machine(
        self,
        machine_id: Optional[int] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lấy danh sách các crash của một máy, tuỳ chọn lọc theo khoảng thời gian."""
        conn = self._get_connection()
        query = "SELECT * FROM crash WHERE 1=1"
        params: List[Any] = []

        if machine_id is not None:
            query += " AND machine_id = ?"
            params.append(machine_id)
        if from_date:
            query += " AND crash_time_utc >= ?"
            params.append(from_date)
        if to_date:
            query += " AND crash_time_utc <= ?"
            params.append(to_date)

        query += " ORDER BY crash_time_utc ASC"
        cursor = conn.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def insert_finding(self, finding: Finding) -> int:
        """Lưu kết luận chẩn đoán vào cơ sở dữ liệu."""
        conn = self._get_connection()
        sql = """
        INSERT INTO finding (
            scope, crash_id, machine_id, suspect, score, confidence, rationale, evidence_ids, next_steps
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        ev_ids_str = ",".join(str(i) for i in finding.evidence_ids) if finding.evidence_ids else ""
        next_steps_json = json.dumps(finding.next_steps or [], ensure_ascii=False)

        with conn:
            cursor = conn.execute(
                sql,
                (
                    finding.scope,
                    finding.crash_id,
                    finding.machine_id,
                    finding.suspect,
                    finding.score,
                    finding.confidence,
                    finding.rationale,
                    ev_ids_str,
                    next_steps_json,
                ),
            )
            finding.id = cursor.lastrowid
            return finding.id

    def get_findings_by_crash(self, crash_id: int) -> List[Dict[str, Any]]:
        """Lấy danh sách các kết luận gắn với một vụ sập."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM finding WHERE crash_id = ? ORDER BY id DESC",
            (crash_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        for r in rows:
            r["next_steps"] = json.loads(r["next_steps"]) if r.get("next_steps") else []
            r["evidence_ids"] = [int(i) for i in r["evidence_ids"].split(",") if i.strip()] if r.get("evidence_ids") else []
        return rows

    def get_findings_by_machine(self, machine_id: int) -> List[Dict[str, Any]]:
        """Lấy danh sách các kết luận tổng thể của một máy."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM finding WHERE machine_id = ? AND scope = 'machine' ORDER BY id DESC",
            (machine_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        for r in rows:
            r["next_steps"] = json.loads(r["next_steps"]) if r.get("next_steps") else []
            r["evidence_ids"] = [int(i) for i in r["evidence_ids"].split(",") if i.strip()] if r.get("evidence_ids") else []
        return rows


