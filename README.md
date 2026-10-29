# DumpAnalyzer — Công Cụ Phân Tích Dump (BSOD) & Windows Event Log

DumpAnalyzer là phần mềm hỗ trợ nhân viên kỹ thuật và quản trị viên IT tự động hóa quá trình phân tích màn hình xanh (BSOD) kết hợp với Windows Event Log, giúp khoanh vùng nhanh nguyên nhân sự cố phần cứng, driver hoặc xung đột phần mềm.

---

## 1. Hướng Dẫn Sử Dụng Nhanh (Dành Cho Nhân Viên IT)

1. **Kiểm tra môi trường:**
   - Nhấp đúp vào file `run_cli.bat` để chạy kiểm tra quyền Administrator, công cụ `cdb.exe` và thư mục dump.
2. **Khởi chạy dòng lệnh:**
   - Mở cửa sổ Command Prompt tại thư mục dự án và gõ:
     ```cmd
     run_cli.bat --help
     ```
3. **Xem hướng dẫn cấu hình:**
   - Bạn có thể chỉnh sửa file `config/settings.yaml` bằng Notepad để điều chỉnh đường dẫn `cdb.exe`, thư mục quét dump hoặc thời gian timeout.

---

## 2. Cấu Trúc Dự Án

```
DumpAnalyzer/
├── pyproject.toml              # Định nghĩa gói và thư viện phụ thuộc
├── run_cli.bat                 # Khởi chạy dòng lệnh một cú nhấp đúp
├── run_gui.bat                 # Khởi chạy giao diện người dùng
├── config/
│   ├── settings.yaml           # Cấu hình hệ thống (đường dẫn cdb, symbol, timeout...)
│   ├── rules/
│   │   ├── bugcheck_rules.yaml # Quy tắc suy luận theo mã Bug Check
│   │   ├── driver_map.yaml     # Ánh xạ tên driver bên thứ ba sang thiết bị
│   │   ├── event_rules.yaml    # Quy tắc chấm điểm từ Event Log
│   │   └── patterns.yaml       # Mẫu hình đa crash
│   └── data/
│       └── bugcheck_codes.json # Cơ sở dữ liệu 380 mã Bug Check Microsoft
├── src/dumpanalyzer/           # Mã nguồn chính của chương trình
│   ├── core/                   # Cấu hình, mô hình dữ liệu, xử lý múi giờ UTC, logging
│   ├── collectors/             # Bộ thu thập file dump, Event Log, thông tin phần cứng
│   ├── analyzer/               # Bộ đọc header dump và bộ chạy cdb.exe ngầm
│   ├── storage/                # Quản lý cơ sở dữ liệu SQLite
│   ├── engine/                 # Bộ nạp quy tắc và thuật toán chấm điểm
│   ├── report/                 # Bộ xuất báo cáo HTML và Excel
│   ├── cli.py                  # Giao diện dòng lệnh
│   └── gui/                    # Giao diện đồ hoạ (PySide6)
├── tests/                      # Bộ kiểm thử tự động (pytest)
└── docs/                       # Tài liệu hướng dẫn chi tiết
    ├── ARCHITECTURE.md         # Khảo sát tài sản và kiến trúc hệ thống
    ├── RULES_GUIDE.md          # Hướng dẫn người dùng IT tự chỉnh sửa quy tắc
    └── TESTING_WITH_NOTMYFAULT.md # Hướng dẫn tạo dump thử nghiệm
```
