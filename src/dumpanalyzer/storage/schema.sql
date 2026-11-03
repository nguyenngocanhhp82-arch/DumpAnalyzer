-- ==============================================================================
-- SCHEMA CƠ SỞ DỮ LIỆU SQLITE CHO DUMPANALYZER
-- Lưu trữ thông tin máy tính, các lần sập (crash), bằng chứng (evidence) và kết luận (finding)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS machine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    model TEXT,
    bios TEXT,
    cpu TEXT,
    os_build TEXT
);

CREATE TABLE IF NOT EXISTS crash (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id INTEGER REFERENCES machine(id) ON DELETE CASCADE,
    dump_path TEXT,              -- Đường dẫn file dump đã copy ra thư mục làm việc
    dump_sha256 TEXT UNIQUE,     -- Khóa băm SHA-256 chống phân tích trùng lặp (cache key)
    dump_type TEXT,              -- 'mini', 'kernel', 'full', hoặc 'none'
    crash_time_utc TEXT,         -- Thời gian sập chuẩn hoá UTC (ISO-8601: YYYY-MM-DDTHH:MM:SSZ)
    bugcheck_code TEXT,          -- Ví dụ: '0x124', '0x133'
    bugcheck_name TEXT,          -- Ví dụ: 'WHEA_UNCORRECTABLE_ERROR'
    p1 TEXT,
    p2 TEXT,
    p3 TEXT,
    p4 TEXT,
    image_name TEXT,
    module_name TEXT,
    process_name TEXT,
    failure_bucket_id TEXT,
    uptime_seconds INTEGER DEFAULT 0,
    cdb_raw_output TEXT,         -- LUÔN lưu output thô để phân tích lại khi đổi luật
    analyzed_by TEXT,            -- 'cdb', 'header_only', hoặc 'none'
    crash_time_source TEXT DEFAULT 'unknown', -- 'header', 'mtime', 'cdb', 'eventlog_6008', 'estimated', 'kp41'
    suspect_driver TEXT DEFAULT ''            -- Driver nghi vấn phát hiện trong stack trace
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crash_id INTEGER REFERENCES crash(id) ON DELETE CASCADE,
    kind TEXT,                   -- 'dump', 'eventlog', 'smart', 'update', 'driver', 'thermal'
    source TEXT,                 -- Ví dụ: 'Microsoft-Windows-WHEA-Logger', 'Disk', 'cdb'
    event_id INTEGER,
    time_utc TEXT,
    summary TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS finding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT,                  -- 'crash' hoặc 'machine'
    crash_id INTEGER REFERENCES crash(id) ON DELETE CASCADE,
    machine_id INTEGER REFERENCES machine(id) ON DELETE CASCADE,
    suspect TEXT,                -- 'ram', 'storage', 'gpu', 'psu', 'thermal', 'cpu', 'driver:<tên>', 'update', 'unknown'
    score REAL,                  -- 0.0 - 100.0
    confidence TEXT,             -- 'thấp', 'trung bình', 'cao'
    rationale TEXT,
    evidence_ids TEXT,           -- Danh sách id evidence, phân cách bằng dấu phẩy
    next_steps TEXT              -- JSON string danh sách các bước kiểm tra theo thứ tự từ dễ đến khó
);

CREATE INDEX IF NOT EXISTS idx_crash_sha256 ON crash(dump_sha256);
CREATE INDEX IF NOT EXISTS idx_crash_time ON crash(crash_time_utc);
CREATE INDEX IF NOT EXISTS idx_evidence_crash ON evidence(crash_id);
CREATE INDEX IF NOT EXISTS idx_finding_crash ON finding(crash_id);
CREATE INDEX IF NOT EXISTS idx_finding_machine ON finding(machine_id);
