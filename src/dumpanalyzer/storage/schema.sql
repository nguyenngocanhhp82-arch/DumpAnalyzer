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
    analyzed_by TEXT,            -- 'cdb', 'triage_native', 'header_only', hoặc 'none'
    crash_time_source TEXT DEFAULT 'unknown', -- 'header', 'mtime', 'cdb', 'eventlog_6008', 'estimated', 'kp41'
    suspect_driver TEXT DEFAULT '',           -- Driver nghi vấn phát hiện trong stack trace
    extra_json TEXT DEFAULT '{}',             -- Dữ liệu mở rộng JSON (errrec, chkimg, driver_age)
    exception_code TEXT DEFAULT '',           -- Mã ngoại lệ (ví dụ: '0xC0000005')
    exception_address TEXT DEFAULT '',        -- Địa chỉ ngoại lệ (ví dụ: '0xFFFFF80585ED8334')
    exception_module TEXT DEFAULT '',         -- Module ngoại lệ (ví dụ: 'ntoskrnl.exe')
    triage_json TEXT DEFAULT '{}'             -- Kết quả triage reader JSON (giới hạn <= 256KB)
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crash_id INTEGER REFERENCES crash(id) ON DELETE CASCADE,
    kind TEXT,                   -- 'dump', 'eventlog', 'smart', 'update', 'driver', 'thermal', 'sysinfo', 'hwtest'
    source TEXT,                 -- Ví dụ: 'Microsoft-Windows-WHEA-Logger', 'Disk', 'cdb'
    event_id INTEGER,
    time_utc TEXT,
    summary TEXT,
    detail TEXT,
    strength TEXT DEFAULT 'weak',       -- 'strong', 'medium', 'weak'
    polarity TEXT DEFAULT 'support',    -- 'support', 'refute'
    group_id TEXT DEFAULT ''            -- Nhóm bằng chứng độc lập
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
    next_steps TEXT,             -- JSON string danh sách các bước kiểm tra theo thứ tự từ dễ đến khó
    suspicion_share REAL DEFAULT 0.0,
    confidence_rationale TEXT DEFAULT ''
);

-- Thông tin phần cứng thu thập từ PowerShell / CIM (Phần 1.3)
CREATE TABLE IF NOT EXISTS system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id INTEGER REFERENCES machine(id) ON DELETE CASCADE,
    collected_at TEXT,
    category TEXT,               -- 'ram', 'disk', 'bios', 'cpu', 'gpu'
    key TEXT,
    value TEXT,
    raw_json TEXT
);

-- Danh sách tài sản nhập từ file CSV AppSheet (Phần 1.4)
CREATE TABLE IF NOT EXISTS asset_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE,
    purchase_date TEXT,
    warranty_expiry TEXT,
    repair_count INTEGER DEFAULT 0,
    ram TEXT,
    notes TEXT,
    raw_json TEXT
);

-- Phản hồi đánh giá kết quả từ IT (Phần 2.1)
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id INTEGER REFERENCES machine(id) ON DELETE SET NULL,
    analysis_ref TEXT,
    predicted_group TEXT,
    predicted_confidence TEXT,
    verdict TEXT,                -- 'dung', 'sai', 'chua_ro'
    actual_cause TEXT,
    note TEXT,
    created_at TEXT
);

-- Lịch sử chạy bài kiểm tra phần cứng (Phần 4.1)
CREATE TABLE IF NOT EXISTS test_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id INTEGER REFERENCES machine(id) ON DELETE CASCADE,
    test_id TEXT,
    status TEXT,                 -- 'passed', 'failed', 'inconclusive', 'pending', 'not_run'
    details TEXT,
    started_at TEXT,
    finished_at TEXT,
    raw_output TEXT
);

-- Trạng thái sẵn sàng ghi dump của các máy (Đợt 04 - Phần 9.1)
CREATE TABLE IF NOT EXISTS dump_readiness (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    collected_at_utc TEXT NOT NULL,
    source TEXT NOT NULL,                  -- local | share_json | remote
    status TEXT NOT NULL,                  -- READY | READY_PENDING_REBOOT | ATTENTION | BLOCKED | UNKNOWN
    proof_level TEXT NOT NULL DEFAULT 'none',
    crash_dump_enabled INTEGER,            -- NULL nếu không tồn tại hoặc không đọc được
    registry_read_ok INTEGER NOT NULL DEFAULT 1,
    pagefile_state TEXT,                   -- ok | missing | unknown
    free_disk_gb REAL,
    ram_gb REAL,
    last_boot_time_utc TEXT,
    pending_reboot INTEGER NOT NULL DEFAULT 0,
    reason_codes_json TEXT,
    raw_json TEXT,
    UNIQUE(hostname, collected_at_utc)
);

-- Nhật ký thay đổi cấu hình ghi dump (Đợt 04 - Phần 9.1)
CREATE TABLE IF NOT EXISTS dump_config_change (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    changed_at_utc TEXT NOT NULL,
    actor TEXT,
    method TEXT NOT NULL,                  -- local | remote | package
    action TEXT NOT NULL,                  -- enable | rollback | upgrade_small_to_auto | pagefile_fix
    old_values_json TEXT,
    new_values_json TEXT,
    backup_path TEXT,
    result TEXT NOT NULL,                  -- success | failed | cancelled | blocked
    message TEXT,
    reboot_required INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_crash_sha256 ON crash(dump_sha256);
CREATE INDEX IF NOT EXISTS idx_crash_time ON crash(crash_time_utc);
CREATE INDEX IF NOT EXISTS idx_evidence_crash ON evidence(crash_id);
CREATE INDEX IF NOT EXISTS idx_finding_crash ON finding(crash_id);
CREATE INDEX IF NOT EXISTS idx_finding_machine ON finding(machine_id);
CREATE INDEX IF NOT EXISTS idx_sysinfo_machine ON system_info(machine_id);
CREATE INDEX IF NOT EXISTS idx_asset_hostname ON asset_info(hostname);
CREATE INDEX IF NOT EXISTS idx_feedback_machine ON feedback(machine_id);
CREATE INDEX IF NOT EXISTS idx_testrun_machine ON test_run(machine_id);
CREATE INDEX IF NOT EXISTS idx_dump_readiness_host ON dump_readiness(hostname);
CREATE INDEX IF NOT EXISTS idx_dump_readiness_time ON dump_readiness(collected_at_utc);
CREATE INDEX IF NOT EXISTS idx_dump_config_change_host ON dump_config_change(hostname);


