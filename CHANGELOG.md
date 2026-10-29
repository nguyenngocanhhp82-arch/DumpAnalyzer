# NHẬT KÝ THAY ĐỔI (CHANGELOG) — DumpAnalyzer

Mọi thay đổi quan trọng của dự án DumpAnalyzer được ghi lại tại tài liệu này theo từng phiên bản và ngày tháng thực hiện.

---

## [v0.1] - 2026-10-29

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
