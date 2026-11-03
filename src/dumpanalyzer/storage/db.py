"""
Quản lý kết nối và thao tác với Cơ sở dữ liệu SQLite cho DumpAnalyzer.
Đảm bảo lưu trữ bền vững các vụ sập, bằng chứng và kết luận chẩn đoán.
"""

import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dumpanalyzer.core.config import get_project_root
from dumpanalyzer.core.models import MachineInfo, Crash, Evidence, Finding


def _find_schema_file() -> Path:
    """Xác định đường dẫn file schema.sql tin cậy cho cả môi trường dev lẫn đóng gói PyInstaller."""
    tried = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        tried.append(Path(base) / "dumpanalyzer" / "storage" / "schema.sql")
        tried.append(Path(base) / "storage" / "schema.sql")
    tried.append(Path(__file__).resolve().parent / "schema.sql")
    for p in tried:
        if p.is_file():
            return p
    raise FileNotFoundError(
        "Không tìm thấy schema.sql. Đã thử:\n  " + "\n  ".join(str(p) for p in tried)
        + "\nGợi ý: bản đóng gói thiếu file dữ liệu, hãy build lại bằng DumpAnalyzer.spec mới."
    )


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
        schema_file = _find_schema_file()

        with open(schema_file, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        conn = self._get_connection()
        with conn:
            conn.executescript(schema_sql)
            # Migration tự động bổ sung cột cho DB đã tồn tại
            # Bảng crash
            cursor = conn.execute("PRAGMA table_info(crash)")
            crash_cols = {row[1] for row in cursor.fetchall()}
            if "crash_time_source" not in crash_cols:
                conn.execute("ALTER TABLE crash ADD COLUMN crash_time_source TEXT DEFAULT 'unknown';")
            if "suspect_driver" not in crash_cols:
                conn.execute("ALTER TABLE crash ADD COLUMN suspect_driver TEXT DEFAULT '';")
            if "extra_json" not in crash_cols:
                conn.execute("ALTER TABLE crash ADD COLUMN extra_json TEXT DEFAULT '{}';")

            # Bảng evidence
            cursor = conn.execute("PRAGMA table_info(evidence)")
            ev_cols = {row[1] for row in cursor.fetchall()}
            if "strength" not in ev_cols:
                conn.execute("ALTER TABLE evidence ADD COLUMN strength TEXT DEFAULT 'weak';")
            if "polarity" not in ev_cols:
                conn.execute("ALTER TABLE evidence ADD COLUMN polarity TEXT DEFAULT 'support';")
            if "group_id" not in ev_cols:
                conn.execute("ALTER TABLE evidence ADD COLUMN group_id TEXT DEFAULT '';")

            # Bảng finding
            cursor = conn.execute("PRAGMA table_info(finding)")
            finding_cols = {row[1] for row in cursor.fetchall()}
            if "suspicion_share" not in finding_cols:
                conn.execute("ALTER TABLE finding ADD COLUMN suspicion_share REAL DEFAULT 0.0;")
            if "confidence_rationale" not in finding_cols:
                conn.execute("ALTER TABLE finding ADD COLUMN confidence_rationale TEXT DEFAULT '';")


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
            uptime_seconds, cdb_raw_output, analyzed_by,
            crash_time_source, suspect_driver, extra_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            getattr(crash, "crash_time_source", "unknown") or "unknown",
            getattr(crash, "suspect_driver", "") or "",
            getattr(crash, "extra_json", "{}") or "{}",
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
        suspect_driver: str = "",
        extra_json: Optional[str] = None,
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
            analyzed_by = ?,
            suspect_driver = CASE WHEN ? != '' THEN ? ELSE suspect_driver END,
            extra_json = CASE WHEN ? IS NOT NULL THEN ? ELSE extra_json END
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
                    suspect_driver,
                    suspect_driver,
                    extra_json,
                    extra_json,
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
        INSERT INTO evidence (crash_id, kind, source, event_id, time_utc, summary, detail, strength, polarity, group_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        strength = getattr(ev, "strength", "weak") or "weak"
        polarity = getattr(ev, "polarity", "support") or "support"
        group_id = getattr(ev, "group_id", "") or ""
        with conn:
            cursor = conn.execute(
                sql,
                (
                    ev.crash_id,
                    ev.kind,
                    ev.source,
                    ev.event_id,
                    ev.time_utc,
                    ev.summary,
                    ev.detail,
                    strength,
                    polarity,
                    group_id,
                ),
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
            scope, crash_id, machine_id, suspect, score, confidence, rationale, evidence_ids, next_steps,
            suspicion_share, confidence_rationale
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        ev_ids_str = ",".join(str(i) for i in finding.evidence_ids) if finding.evidence_ids else ""
        next_steps_json = json.dumps(finding.next_steps or [], ensure_ascii=False)
        suspicion_share = getattr(finding, "suspicion_share", 0.0) or 0.0
        conf_rationale = getattr(finding, "confidence_rationale", "") or ""

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
                    suspicion_share,
                    conf_rationale,
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

    # =========================================================================
    # CÁC PHƯƠNG THỨC MỚI CHO ĐỢT CẬP NHẬT 03 (v1.1.0)
    # =========================================================================

    def insert_system_info(
        self,
        machine_id: int,
        category: str,
        key: str,
        value: str,
        raw_json: str = "{}",
        collected_at: Optional[str] = None,
    ) -> int:
        """Lưu bản ghi thông tin hệ thống (Phần 1.3)."""
        import datetime
        conn = self._get_connection()
        at_utc = collected_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
        INSERT INTO system_info (machine_id, collected_at, category, key, value, raw_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(sql, (machine_id, at_utc, category, key, value, raw_json))
            return cursor.lastrowid

    def get_system_info_by_machine(
        self, machine_id: int, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Lấy thông tin hệ thống của máy theo danh mục."""
        conn = self._get_connection()
        if category:
            cursor = conn.execute(
                "SELECT * FROM system_info WHERE machine_id = ? AND category = ? ORDER BY id ASC",
                (machine_id, category),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM system_info WHERE machine_id = ? ORDER BY category, id ASC",
                (machine_id,),
            )
        return [dict(r) for r in cursor.fetchall()]

    def upsert_asset_info(
        self,
        hostname: str,
        purchase_date: str = "",
        warranty_expiry: str = "",
        repair_count: int = 0,
        ram: str = "",
        notes: str = "",
        raw_json: str = "{}",
    ) -> int:
        """Thêm mới hoặc cập nhật thông tin thiết bị từ file CSV AppSheet (Phần 1.4)."""
        conn = self._get_connection()
        clean_host = hostname.strip().upper()
        sql = """
        INSERT INTO asset_info (hostname, purchase_date, warranty_expiry, repair_count, ram, notes, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            purchase_date = excluded.purchase_date,
            warranty_expiry = excluded.warranty_expiry,
            repair_count = excluded.repair_count,
            ram = excluded.ram,
            notes = excluded.notes,
            raw_json = excluded.raw_json
        """
        with conn:
            cursor = conn.execute(
                sql,
                (clean_host, purchase_date, warranty_expiry, repair_count, ram, notes, raw_json),
            )
            return cursor.lastrowid

    def get_asset_info_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Tra cứu thông tin thiết bị từ bảng asset_info theo hostname (không phân biệt hoa thường)."""
        conn = self._get_connection()
        clean_host = hostname.strip().upper()
        cursor = conn.execute("SELECT * FROM asset_info WHERE hostname = ?", (clean_host,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def insert_feedback(
        self,
        machine_id: Optional[int],
        analysis_ref: str,
        predicted_group: str,
        predicted_confidence: str,
        verdict: str,
        actual_cause: str = "",
        note: str = "",
        created_at: Optional[str] = None,
    ) -> int:
        """Lưu đánh giá phản hồi từ kỹ thuật viên IT (Phần 2.1)."""
        import datetime
        conn = self._get_connection()
        at_utc = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
        INSERT INTO feedback (
            machine_id, analysis_ref, predicted_group, predicted_confidence, verdict, actual_cause, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(
                sql,
                (
                    machine_id,
                    analysis_ref,
                    predicted_group,
                    predicted_confidence,
                    verdict,
                    actual_cause,
                    note,
                    at_utc,
                ),
            )
            return cursor.lastrowid

    add_feedback = insert_feedback

    def list_feedback(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lấy danh sách các phản hồi đã ghi nhận."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_feedback_stats(self) -> Dict[str, Any]:
        """
        Tính toán thống kê tỷ lệ độ chính xác theo phản hồi (Phần 2.1).
        Chỉ tính tỷ lệ khi có tối thiểu 10 ca đánh giá.
        """
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM feedback")
        all_fb = [dict(r) for r in cursor.fetchall()]
        total = len(all_fb)

        stats: Dict[str, Any] = {
            "total_count": total,
            "total": total,
            "sufficient_data": total >= 10,
            "message": "Đủ dữ liệu thống kê" if total >= 10 else "chưa đủ dữ liệu (cần tối thiểu 10 ca có đánh giá)",
            "verdict_counts": {"dung": 0, "sai": 0, "chua_ro": 0},
            "by_predicted_group": {},
            "by_confidence": {},
            "accuracy_rate": None,
        }

        for fb in all_fb:
            v = fb.get("verdict", "chua_ro")
            stats["verdict_counts"][v] = stats["verdict_counts"].get(v, 0) + 1

            grp = fb.get("predicted_group", "unknown")
            if grp not in stats["by_predicted_group"]:
                stats["by_predicted_group"][grp] = {"total": 0, "dung": 0, "sai": 0, "chua_ro": 0}
            stats["by_predicted_group"][grp]["total"] += 1
            stats["by_predicted_group"][grp][v] = stats["by_predicted_group"][grp].get(v, 0) + 1

            conf = fb.get("predicted_confidence", "unknown")
            if conf not in stats["by_confidence"]:
                stats["by_confidence"][conf] = {"total": 0, "dung": 0, "sai": 0, "chua_ro": 0}
            stats["by_confidence"][conf]["total"] += 1
            stats["by_confidence"][conf][v] = stats["by_confidence"][conf].get(v, 0) + 1

        if total >= 10:
            decisive = stats["verdict_counts"]["dung"] + stats["verdict_counts"]["sai"]
            if decisive > 0:
                stats["accuracy_rate"] = round((stats["verdict_counts"]["dung"] / decisive) * 100, 1)

        return stats

    def insert_test_run(
        self,
        machine_id: int,
        test_id: str,
        status: str = "pending",
        details: str = "",
        started_at: str = "",
        finished_at: str = "",
        raw_output: str = "",
    ) -> int:
        """Lưu một lần thực thi kiểm tra phần cứng (Phần 4.1)."""
        import datetime
        conn = self._get_connection()
        st_at = started_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
        INSERT INTO test_run (machine_id, test_id, status, details, started_at, finished_at, raw_output)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(
                sql, (machine_id, test_id, status, details, st_at, finished_at, raw_output)
            )
            return cursor.lastrowid

    def update_test_run(
        self,
        run_id: int,
        status: str,
        details: str = "",
        finished_at: str = "",
        raw_output: str = "",
    ) -> bool:
        """Cập nhật trạng thái và kết quả lần kiểm tra phần cứng."""
        import datetime
        conn = self._get_connection()
        fn_at = finished_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
        UPDATE test_run
        SET status = ?,
            details = CASE WHEN ? != '' THEN ? ELSE details END,
            finished_at = ?,
            raw_output = CASE WHEN ? != '' THEN ? ELSE raw_output END
        WHERE id = ?
        """
        with conn:
            cursor = conn.execute(sql, (status, details, details, fn_at, raw_output, raw_output, run_id))
            return cursor.rowcount > 0

    def get_test_runs_by_machine(
        self, machine_id: int, test_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Lấy danh sách các lần chạy kiểm tra phần cứng của máy."""
        conn = self._get_connection()
        if test_id:
            cursor = conn.execute(
                "SELECT * FROM test_run WHERE machine_id = ? AND test_id = ? ORDER BY id DESC",
                (machine_id, test_id),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM test_run WHERE machine_id = ? ORDER BY id DESC",
                (machine_id,),
            )
        return [dict(r) for r in cursor.fetchall()]

    def insert_dump_readiness(self, record: Dict[str, Any]) -> int:
        """Lưu hoặc cập nhật trạng thái sẵn sàng ghi dump của một máy (Đợt 04)."""
        import datetime
        conn = self._get_connection()
        hostname = record.get("hostname", "UNKNOWN")
        c_at = record.get("collected_at_utc") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        source = record.get("source", "local")
        status = record.get("status", "UNKNOWN")
        proof_level = record.get("proof_level", "none")
        cde = record.get("crash_dump_enabled")
        reg_ok = 1 if record.get("registry_read_ok", True) else 0
        pf_state = record.get("pagefile_state", "unknown")
        free_disk = record.get("free_disk_gb")
        ram = record.get("ram_gb")
        last_boot = record.get("last_boot_time_utc")
        pending = 1 if record.get("pending_reboot") else 0

        rc_json = record.get("reason_codes_json")
        if rc_json is None and "reason_codes" in record:
            rc_json = json.dumps(record["reason_codes"], ensure_ascii=False)
        elif rc_json is None:
            rc_json = "[]"

        raw_j = record.get("raw_json")
        if raw_j is None:
            raw_j = json.dumps(record, ensure_ascii=False)

        sql = """
        INSERT INTO dump_readiness (
            hostname, collected_at_utc, source, status, proof_level,
            crash_dump_enabled, registry_read_ok, pagefile_state, free_disk_gb,
            ram_gb, last_boot_time_utc, pending_reboot, reason_codes_json, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname, collected_at_utc) DO UPDATE SET
            source=excluded.source,
            status=excluded.status,
            proof_level=excluded.proof_level,
            crash_dump_enabled=excluded.crash_dump_enabled,
            registry_read_ok=excluded.registry_read_ok,
            pagefile_state=excluded.pagefile_state,
            free_disk_gb=excluded.free_disk_gb,
            ram_gb=excluded.ram_gb,
            last_boot_time_utc=excluded.last_boot_time_utc,
            pending_reboot=excluded.pending_reboot,
            reason_codes_json=excluded.reason_codes_json,
            raw_json=excluded.raw_json
        """
        with conn:
            cursor = conn.execute(
                sql,
                (
                    hostname, c_at, source, status, proof_level,
                    cde, reg_ok, pf_state, free_disk, ram,
                    last_boot, pending, rc_json, raw_j
                )
            )
            return cursor.lastrowid

    def get_latest_dump_readiness(self, hostname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Lấy bản ghi trạng thái sẵn sàng ghi dump gần nhất của một máy (hoặc toàn bộ)."""
        conn = self._get_connection()
        if hostname:
            cursor = conn.execute(
                "SELECT * FROM dump_readiness WHERE hostname = ? ORDER BY collected_at_utc DESC LIMIT 1",
                (hostname,)
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM dump_readiness ORDER BY collected_at_utc DESC LIMIT 1"
            )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_dump_readiness(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lấy danh sách trạng thái sẵn sàng gần nhất cho từng máy tính."""
        conn = self._get_connection()
        sql = """
        SELECT dr.* FROM dump_readiness dr
        INNER JOIN (
            SELECT hostname, MAX(collected_at_utc) as max_time
            FROM dump_readiness
            GROUP BY hostname
        ) latest ON dr.hostname = latest.hostname AND dr.collected_at_utc = latest.max_time
        ORDER BY dr.hostname ASC
        LIMIT ?
        """
        cursor = conn.execute(sql, (limit,))
        return [dict(r) for r in cursor.fetchall()]

    def insert_dump_config_change(self, change: Dict[str, Any]) -> int:
        """Ghi nhận nhật ký thay đổi cấu hình ghi dump (audit log)."""
        import datetime
        conn = self._get_connection()
        hostname = change.get("hostname", "UNKNOWN")
        c_at = change.get("changed_at_utc") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        actor = change.get("actor", "")
        method = change.get("method", "local")
        action = change.get("action", "enable")

        old_val = change.get("old_values_json")
        if old_val is None and "old_values" in change:
            old_val = json.dumps(change["old_values"], ensure_ascii=False)
        elif old_val is None and "previous_mode" in change:
            old_val = json.dumps({"CrashDumpEnabled": change["previous_mode"], "previous_mode": change["previous_mode"]}, ensure_ascii=False)
        elif old_val is None:
            old_val = "{}"

        new_val = change.get("new_values_json")
        if new_val is None and "new_values" in change:
            new_val = json.dumps(change["new_values"], ensure_ascii=False)
        elif new_val is None and "new_mode" in change:
            new_val = json.dumps({"CrashDumpEnabled": change["new_mode"], "new_mode": change["new_mode"]}, ensure_ascii=False)
        elif new_val is None:
            new_val = "{}"

        backup_p = change.get("backup_path", "")
        result = change.get("result", "success")
        msg = change.get("message", change.get("notes", ""))
        reboot = 1 if change.get("reboot_required") else 0

        sql = """
        INSERT INTO dump_config_change (
            hostname, changed_at_utc, actor, method, action,
            old_values_json, new_values_json, backup_path, result,
            message, reboot_required
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with conn:
            cursor = conn.execute(
                sql,
                (
                    hostname, c_at, actor, method, action,
                    old_val, new_val, backup_p, result, msg, reboot
                )
            )
            return cursor.lastrowid

    def _enrich_config_change(self, row_dict: Dict[str, Any]) -> Dict[str, Any]:
        res = dict(row_dict)
        if res.get("new_values_json"):
            try:
                nv = json.loads(res["new_values_json"])
                if "new_mode" in nv:
                    res["new_mode"] = nv["new_mode"]
                elif "CrashDumpEnabled" in nv:
                    res["new_mode"] = nv["CrashDumpEnabled"]
            except Exception:
                pass
        if res.get("old_values_json"):
            try:
                ov = json.loads(res["old_values_json"])
                if "previous_mode" in ov:
                    res["previous_mode"] = ov["previous_mode"]
                elif "CrashDumpEnabled" in ov:
                    res["previous_mode"] = ov["CrashDumpEnabled"]
            except Exception:
                pass
        return res

    def get_latest_dump_config_change(self, hostname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Lấy bản ghi thay đổi cấu hình gần nhất của máy tính (hoặc toàn bộ)."""
        conn = self._get_connection()
        if hostname:
            cursor = conn.execute(
                "SELECT * FROM dump_config_change WHERE hostname = ? ORDER BY changed_at_utc DESC LIMIT 1",
                (hostname,)
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM dump_config_change ORDER BY changed_at_utc DESC LIMIT 1"
            )
        row = cursor.fetchone()
        return self._enrich_config_change(dict(row)) if row else None

    def list_dump_config_changes(
        self, hostname: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Lấy danh sách nhật ký thay đổi cấu hình ghi dump."""
        conn = self._get_connection()
        if hostname:
            cursor = conn.execute(
                "SELECT * FROM dump_config_change WHERE hostname = ? ORDER BY changed_at_utc DESC LIMIT ?",
                (hostname, limit),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM dump_config_change ORDER BY changed_at_utc DESC LIMIT ?",
                (limit,),
            )
        return [self._enrich_config_change(dict(r)) for r in cursor.fetchall()]




