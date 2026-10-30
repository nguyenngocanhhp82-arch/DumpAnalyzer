# DumpAnalyzer — Công Cụ Phân Tích Màn Hình Xanh (BSOD) & Windows Event Log

**DumpAnalyzer** là giải pháp phần mềm chuyên dụng hỗ trợ nhân viên kỹ thuật và quản trị viên IT tự động hóa toàn diện quy trình chẩn đoán sự cố màn hình xanh (BSOD) và sập nguồn đột ngột trên hệ điều hành Windows.

Công cụ kết hợp giữa **phân tích nhị phân Dump (hoặc WinDbg `cdb.exe`)** với **tương quan thời gian thực sự kiện Windows Event Log (Event 41, 1001, WHEA, Disk, GPU)**, áp dụng thuật toán khoanh vùng xác suất theo quy tắc YAML để đưa ra kết luận chẩn đoán nguyên nhân gốc rễ và đề xuất lộ trình khắc phục từ **DỄ đến KHÓ**.

---

## 1. TÍNH NĂNG NỔI BẬT

- **Hỗ trợ đầy đủ các trường hợp máy:**
  + Máy có dump và có `cdb.exe`: Phân tích sâu call stack, trích xuất driver lỗi, đối chiếu bộ nhớ.
  + Máy có dump nhưng chưa cài `cdb.exe`: Tự động đọc trực tiếp header nhị phân (`header_only`), trích xuất mã Bug Check và 4 tham số.
  + Máy **chưa bật ghi dump** hoặc sập nguồn đột ngột không kịp ghi dump: Chế độ **"Chỉ log" (`log_only`)**, trích xuất mã lỗi thập phân từ Event 41/1001 và đổi sang Hex.
- **Kiểm tra khả năng ghi dump an toàn (`check-dump-config`):**
  + Kiểm tra trạng thái registry `CrashControl`, phân vùng Pagefile, dung lượng trống ổ đĩa và lịch sử `volmgr` 161/162.
  + Hỗ trợ chế độ `--apply` an toàn (tự động sao lưu registry cũ, yêu cầu người dùng xác nhận trực tiếp bằng tay).
- **Phân tích theo lô đa máy (Fleet & Batch Analysis):**
  + Quét cây thư mục chứa dump của hàng chục máy tính khác nhau trong công ty.
  + Tự động phát hiện driver lỗi xuất hiện đồng loạt trên nhiều máy tính (Cross-machine correlation).
- **Giao diện đồ họa PySide6 hiện đại:**
  + Giao diện Dark/Slate sang trọng theo bảng màu công nghiệp, xử lý đa luồng ngầm không gây đơ ứng dụng.
  + 4 Tab nghiệp vụ: **Tổng quan | Chi tiết crash | Kết luận | Cài đặt & Khả năng ghi dump**.
- **Xuất báo cáo chuyên nghiệp:**
  + **Báo cáo HTML độc lập:** Nhúng toàn bộ CSS, biểu đồ thanh tiến độ, sẵn sàng in ấn hoặc lưu PDF.
  + **Báo cáo Excel đa bảng tính (.xlsx):** Tự động định dạng viền, màu sắc và tự co giãn độ rộng cột.
- **Quy tắc mở hoàn toàn bằng YAML:**
  + Kỹ thuật viên IT có thể tự thêm mã lỗi, ánh xạ driver, quy tắc sự kiện mà không cần sửa code.

---

## 2. HƯỚNG DẪN SỬ DỤNG NHANH

### Cách 1: Khởi chạy Giao diện Đồ họa (GUI)
Nhấp đúp chuột vào file:
```cmd
run_gui.bat
```
Hoặc chạy lệnh Python:
```bash
python -m dumpanalyzer.gui.main
```

### Cách 2: Khởi chạy Giao diện Dòng lệnh (CLI)
Nhấp đúp chuột vào file `run_cli.bat` hoặc mở Command Prompt tại thư mục dự án:
```cmd
# 1. Kiểm tra môi trường (cdb.exe, quyền Administrator, thư mục dump):
dumpanalyzer check-env

# 2. Kiểm tra cấu hình ghi dump của máy:
dumpanalyzer check-dump-config

# 3. Kích hoạt tự động ghi dump (yêu cầu Admin và xác nhận):
dumpanalyzer check-dump-config --apply

# 4. Quét và sao chép an toàn các file dump:
dumpanalyzer scan

# 5. Phân tích sâu bằng cdb (nếu có):
dumpanalyzer analyze

# 6. Thu thập và ghép nối sự kiện Windows Event Log:
dumpanalyzer events

# 7. Đưa ra phán quyết nguyên nhân kèm các bước khắc phục:
dumpanalyzer verdict

# 8. Phân tích theo lô thư mục chứa dump của nhiều máy:
dumpanalyzer batch --dir C:\DumpsCongTy --report-html baocao_fleet.html --report-excel baocao_fleet.xlsx

# 9. Kiểm tra tính hợp lệ của tất cả file quy tắc YAML:
dumpanalyzer validate-rules
```

---

## 3. ĐÓNG GÓI THÀNH FILE .EXE (PYINSTALLER)

DumpAnalyzer được cấu hình đóng gói chuẩn dạng thư mục (`--onedir`), giao diện cửa sổ (`--windowed`) và tự yêu cầu quyền Administrator (`--uac-admin`):

1. **Đóng gói thủ công cục bộ (trên máy Windows):**
   - Nhấp đúp vào file `build_exe.bat` hoặc chạy:
     ```cmd
     python build_exe.py
     ```
   - Thư mục phân phối hoàn chỉnh sẽ được tạo tại `dist/DumpAnalyzer/` và file nén `dist/DumpAnalyzer-windows-x64.zip`.
   - File thực thi: `dist/DumpAnalyzer/DumpAnalyzer.exe`
   - Thư mục cấu hình quy tắc nằm ngay bên cạnh: `dist/DumpAnalyzer/config/` (kỹ thuật viên có thể sửa trực tiếp các file YAML mà không cần build lại).

2. **Tự động đóng gói trên GitHub Actions (Khuyến nghị):**
   - Dự án đã tích hợp sẵn GitHub Actions workflow tại `.github/workflows/build.yml`.
   - **Tự động kích hoạt:** Khi push code lên nhánh `main` hoặc gắn tag phiên bản `v*` (ví dụ `git tag v1.0.0 && git push origin v1.0.0`).
   - **Kích hoạt thủ công:** Vào tab **Actions** trên GitHub $\rightarrow$ chọn workflow **"Build & Release DumpAnalyzer"** $\rightarrow$ nhấn **Run workflow**.
   - **Tải file chạy:**
     + **Artifacts:** Tải file `DumpAnalyzer-windows-x64.zip` từ trang kết quả chạy của workflow.
     + **Releases:** Nếu gắn tag `v*` hoặc bật tuỳ chọn tạo release, file zip sẽ tự động được đính kèm vào mục **Releases** của repo.

---

## 4. HƯỚNG DẪN THIẾT LẬP NGOẠI LỆ DIỆT VIRUS (ANTIVIRUS EXCLUSION)

Do các phần mềm đóng gói bằng PyInstaller chạy với quyền Administrator thường bị Windows Defender hoặc các trình diệt virus (Kaspersky, Symantec, Bitdefender) quét nhầm (False Positive), hãy thực hiện thêm thư mục công cụ vào danh sách loại trừ:

### Các bước trên Windows Security (Windows Defender):
1. Mở **Start Menu** $\rightarrow$ gõ **Windows Security** và nhấn Enter.
2. Chọn mục **Virus & threat protection** (Bảo vệ khỏi mối đe dọa & virus).
3. Tại phần *Virus & threat protection settings*, chọn **Manage settings**.
4. Cuộn xuống mục **Exclusions** $\rightarrow$ chọn **Add or remove exclusions**.
5. Bấm **Add an exclusion** $\rightarrow$ chọn **Folder** $\rightarrow$ Trỏ tới thư mục chứa phần mềm `DumpAnalyzer` (hoặc thư mục `dist\DumpAnalyzer`).

---

## 5. TÀI LIỆU KÈM THEO

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Khảo sát tài sản sẵn có và tài liệu thiết kế kiến trúc luồng dữ liệu tổng thể.
- [docs/RULES_GUIDE.md](docs/RULES_GUIDE.md): Cẩm nang hướng dẫn chi tiết cách thêm mã Bug Check, ánh xạ driver, quy tắc Event Log và mẫu hình đa crash.
- [docs/TESTING_WITH_NOTMYFAULT.md](docs/TESTING_WITH_NOTMYFAULT.md): Hướng dẫn tạo dump giả lập an toàn bằng NotMyFault của Microsoft Sysinternals để thử nghiệm công cụ.
- [docs/UPDATE_01.md](docs/UPDATE_01.md): Bản cập nhật đợt 1 về trần độ tin cậy và chế độ log_only.
- [docs/BUG_REPORT_TEMPLATE.md](docs/BUG_REPORT_TEMPLATE.md): Mẫu biểu gửi báo cáo sự cố hoặc yêu cầu cập nhật.
- [CHANGELOG.md](CHANGELOG.md): Nhật ký các phiên bản phát hành từ v0.1 đến v0.6.0.

---

## 6. CẤU TRÚC THƯ MỤC NGUỒN

```text
DumpAnalyzer/
├── pyproject.toml              # Cấu hình gói và thư viện
├── DumpAnalyzer.spec           # Cấu hình đóng gói PyInstaller chuyên dụng
├── build_exe.bat               # Batch script đóng gói file .exe trên Windows
├── run_cli.bat                 # Script chạy CLI nhanh
├── run_gui.bat                 # Script chạy GUI nhanh
├── config/                     # Thư mục cấu hình (đặt cạnh file .exe khi phân phối)
│   ├── settings.yaml           # Cấu hình ngưỡng điểm, đường dẫn, timeout
│   ├── data/
│   │   └── bugcheck_codes.json # 380 mã Bug Check chuẩn Microsoft
│   └── rules/
│       ├── bugcheck_rules.yaml # Quy tắc phân loại lỗi BSOD
│       ├── driver_map.yaml     # Ánh xạ tên file driver sang linh kiện
│       ├── event_rules.yaml    # Quy tắc chấm điểm Windows Event Log
│       └── patterns.yaml       # Mẫu hình đa crash
├── src/dumpanalyzer/
│   ├── analyzer/               # Bộ đọc header, cdb runner, fleet batch analyzer
│   ├── collectors/             # Thu thập dump, dump config, event log, WMI
│   ├── core/                   # Cấu hình, CSDL SQLite, models, UTC timeutil, logging
│   ├── engine/                 # Tương quan sự kiện, nạp rule YAML, chấm điểm, phán quyết
│   ├── gui/                    # Giao diện PySide6 (4 tab, worker ngầm)
│   ├── report/                 # Bộ xuất báo cáo HTML & Excel (.xlsx)
│   └── cli.py                  # Điểm vào dòng lệnh
├── tests/                      # Bộ 85+ kiểm thử tự động (pytest)
└── docs/                       # Tài liệu hướng dẫn chuyên sâu
```
