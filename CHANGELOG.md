# NHẬT KÝ THAY ĐỔI (CHANGELOG) — DumpAnalyzer

Mọi thay đổi quan trọng của dự án DumpAnalyzer được ghi lại tại tài liệu này theo từng phiên bản và ngày tháng thực hiện.

---

## [v0.1.1] - 2026-10-29

### Hoàn thành Phase 1 (MVP Dòng lệnh: Thu Dump & Đọc Header)
- **Module thu thập (`dump_finder.py`):**
  - Quét tìm file `.dmp` đệ quy theo thư mục hoặc file đơn lẻ; hỗ trợ lọc theo ngày (`from_date`, `to_date`).
  - Hàm `copy_dump_safely()`: Sao chép an toàn sang thư mục làm việc `workspace/` trước khi phân tích; tuyệt đối không đụng vào file gốc.
  - Hàm `calculate_sha256()`: Tính mã băm theo khối nhớ 64KB, chống tràn RAM trên các file dump dung lượng lớn.
- **Module phân tích Header nhị phân (`header_parser.py`):**
  - Đọc trực tiếp header `PAGEDU64` của Windows 64-bit Kernel/Complete dump: đọc chính xác `BugCheckCode` tại offset `0x38`, 4 tham số `p1..p4` tại `0x40, 0x48, 0x50, 0x58`, và `SystemTime` tại `0xA0`.
  - Nhận diện Minidump `MDMP`, trích xuất Unix timestamp và stream Exception.
  - Xử lý lỗi mềm khi gặp dump hỏng (`corrupted.dmp`) hoặc file không tồn tại mà không làm sập chương trình.
- **Giao diện dòng lệnh (`cli.py`):**
  - Bổ sung lệnh `dumpanalyzer scan --path <thư_mục> [--from] [--to] [--force]`.
  - In bảng dạng lưới căn chỉnh đẹp mắt: Thời điểm (giờ địa phương), Mã lỗi, Tên lỗi BugCheck, Loại dump, Trạng thái cache (`[CACHE]` / `[MỚI]`), Đường dẫn file.
- **Kiểm thử tự động:**
  - Bổ sung 4 fixture dump mẫu trong `tests/fixtures/` (`kernel_sample_124.dmp`, `kernel_sample_1a.dmp`, `minidump_sample.dmp`, `corrupted.dmp`).
  - Thêm 10 unit test mới, nâng tổng số test lên **22/22 PASSED** (100%).

---

## [v0.1.0] - 2026-10-29

### Khởi tạo & Hoàn thành Phase 0
- **Khảo sát tài sản:** Định vị và lưu vết script công cụ cũ `EventLogAnalyzer.ps1` vào `legacy_tools/`.
- **Cơ sở dữ liệu Bug Check:** Trích xuất đầy đủ 380 mã Bug Check chuẩn Microsoft sang định dạng JSON có cấu trúc tại `config/data/bugcheck_codes.json`.
- **Bộ luật khởi đầu:** Tạo các file cấu hình YAML có comment tiếng Việt:
  - `config/settings.yaml`: Cấu hình hệ thống, cdb, timeout, ngưỡng tin cậy.
  - `config/rules/bugcheck_rules.yaml`: Quy tắc chẩn đoán theo mã Bug Check.
  - `config/rules/driver_map.yaml`: Ánh xạ driver và danh sách `ms_core_modules` (loại trừ ntoskrnl, hal...).
  - `config/rules/event_rules.yaml`: Quy tắc tính trọng số từ các nguồn sự kiện Event Log.
  - `config/rules/patterns.yaml`: Mẫu hình đa crash.
- **Lõi hệ thống:**
  - `src/dumpanalyzer/core/models.py`: Định nghĩa dataclass `Crash`, `Evidence`, `Finding`, `MachineInfo`.
  - `src/dumpanalyzer/core/config.py`: Tự dò tìm `cdb.exe`, kiểm tra quyền Admin, kiểm tra thư mục dump.
  - `src/dumpanalyzer/core/timeutil.py`: Chuẩn hoá thời gian UTC ISO-8601, đổi sang giờ địa phương khi hiển thị.
  - `src/dumpanalyzer/core/logging_setup.py`: Thiết lập ghi log xoay vòng (RotatingFileHandler).
  - `src/dumpanalyzer/storage/schema.sql` & `db.py`: Khởi tạo SQLite, quản lý bảng `crash` và cache theo SHA256.
- **Giao diện dòng lệnh (CLI):**
  - `src/dumpanalyzer/cli.py`: Hỗ trợ `--version` và lệnh `check-env`.
  - Cung cấp `run_cli.bat` và `run_gui.bat` cho người dùng Windows chạy một cú bấm.
- **Kiểm thử tự động:** 12 test cases xanh 100% trong `tests/`.

### Tiếp nhận Cập nhật Đợt 1 (UPDATE_01)
- Tiếp nhận tài liệu `ANTIGRAVITY_UPDATE_01.md` và lưu vào `docs/UPDATE_01.md`.
- Cập nhật tài liệu kiến trúc `docs/ARCHITECTURE.md` bổ sung:
  - Chế độ "chỉ log" khi không có dump (`analyzed_by = 'log_only'`).
  - Quy hoạch Phase 1B: Lệnh `check-dump-config` (mặc định chỉ đọc; sửa registry CrashDumpEnabled an toàn khi có `--apply` và xác nhận).
  - Bổ sung quy tắc lấy mã Bug Check từ Event 41/1001 (chuyển đổi số thập phân sang Hex).
  - Bổ sung bảng trần độ tin cậy mới khi thiếu dump.
  - Ghi nhận đặc tả giao diện đã duyệt cho Phase 5.
  - Quy định đóng gói PyInstaller `--onedir` cho Phase 6.
  - Khởi tạo mẫu báo lỗi chuẩn `docs/BUG_REPORT_TEMPLATE.md`.
