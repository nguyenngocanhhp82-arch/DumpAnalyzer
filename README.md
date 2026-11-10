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
  + 5 Tab nghiệp vụ: **Tổng quan | Chi tiết crash | Kết luận (kèm Feedback) | Kiểm tra phần cứng (Hardware Tests) | Cài đặt**.
- **Khung Kiểm tra phần cứng an toàn (v1.1.0):**
  + Quét ổ đĩa chỉ đọc (`chkdsk /scan`), chặn tuyệt đối các cờ phá hủy `/f`, `/r`, `/spotfix`.
  + Tích hợp Windows Memory Diagnostic (`mdsched.exe`) và tự động đọc kết quả Event Log sau reboot.
  + Nhập kết quả kiểm tra ngoài (MemTest86, OCCT, Prime95) và xuất phiếu hướng dẫn test RAM chuẩn USB boot.
- **Tách Độ tin cậy & Gợi ý bước tiếp theo:**
  + Tách bạch tỷ trọng nghi ngờ `suspicion_share` (%) và mức độ tin cậy `confidence` (cao/trung bình/thấp).
  + Tự động phát hiện dữ liệu còn thiếu và đề xuất lộ trình xử lý từ Tầng 1 (Dễ) đến Tầng 4 (Phức tạp).
- **Vòng phản hồi & Phân tích Đội máy:**
  + Ghi nhận đánh giá đúng/sai từ kỹ thuật viên để thống kê tỷ lệ chính xác.
  + Phân tích đội máy diện rộng theo `FAILURE_BUCKET_ID` và driver lặp lại trên nhiều máy.
  + Nhập dữ liệu danh mục máy tính từ file CSV AppSheet / Google Sheets.
- **Xuất báo cáo chuyên nghiệp:**
  + **Báo cáo HTML độc lập:** Nhúng toàn bộ CSS, biểu đồ thanh tiến độ, sẵn sàng in ấn hoặc lưu PDF.
  + **Báo cáo Excel đa bảng tính (.xlsx):** Bổ sung sheet "Thống kê phản hồi" và sheet "Tổng quan đội máy".
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

# 10. Quản lý phản hồi đánh giá kết luận chẩn đoán:
dumpanalyzer feedback list
dumpanalyzer feedback stats
dumpanalyzer feedback add --verdict dung --predicted-group ram --actual-cause ram --note "Thay RAM hết lỗi"

# 11. Xem tổng quan sự cố diện rộng toàn đội máy:
dumpanalyzer fleet --days 30 --min-machines 3

# 12. Nhập dữ liệu danh mục thiết bị từ file CSV AppSheet:
dumpanalyzer asset import DanhSachThietBi.csv
```

---

## 3. ĐÓNG GÓI THÀNH FILE .EXE (PYINSTALLER)

DumpAnalyzer cung cấp hai hình thức đóng gói linh hoạt đáp ứng mọi nhu cầu cứu hộ và triển khai IT:

1. **Bản Portable 1 file duy nhất (`DumpAnalyzer-Portable.exe` - Khuyến nghị cho USB cứu hộ):**
   - **Chạy ngay lập tức:** Độc lập 100%, không cần cài đặt hay giải nén, chạy trực tiếp từ USB hoặc bất kỳ thư mục nào trên máy tính.
   - **Tích hợp sẵn dữ liệu:** Toàn bộ bảng mã Bug Check, cấu hình `settings.yaml`, 26 quy tắc BSOD, quy tắc Event Log và schema SQLite được nén sẵn bên trong file thực thi.
   - **Tự động điều phối kép (GUI & CLI):**
     - Nhấp đúp chuột từ File Explorer: Khởi chạy giao diện đồ hoạ PySide6 sắc nét, không hiện cửa sổ console đen thừa thãi.
     - Chạy qua dòng lệnh (Command Prompt / PowerShell với các lệnh `scan`, `analyze`, `events`, `check-dump-config`...): Tự động gắn kết console (`AttachConsole`) và in kết quả trực tiếp ra màn hình dòng lệnh.
   - **Cơ chế nạp cấu hình thông minh:**
     - Mặc định: Nạp bộ quy tắc chuẩn tích hợp sẵn trong file portable.
     - Tùy biến IT: Nếu đặt một thư mục `config/` bên cạnh file `DumpAnalyzer-Portable.exe`, phần mềm sẽ tự động ưu tiên nạp cấu hình bên ngoài để IT sửa đổi quy tắc mà không cần biên dịch lại.
     - Dữ liệu bền vững: CSDL `data/dumpanalyzer.db` và nhật ký `logs/` luôn được ghi bên cạnh file thực thi, không bị mất khi thoát.

2. **Bản Thư mục hoàn chỉnh (`dist/DumpAnalyzer/` hoặc `DumpAnalyzer-windows-x64.zip`):**
   - Bao gồm các file thực thi riêng biệt: `DumpAnalyzer.exe` (GUI) và `DumpAnalyzer-cli.exe` (CLI).
   - Thư mục cấu hình `config/` mở sẵn bên ngoài và các file batch `run_gui.bat`, `run_cli.bat` để click chạy nhanh.

3. **Cách đóng gói thủ công cục bộ (trên máy Windows):**
   - Nhấp đúp vào file `build_exe.bat` hoặc chạy:
     ```cmd
     python build_exe.py
     ```
   - Quá trình build sẽ tự động tạo ra cả hai bản phân phối trong thư mục `dist/`:
     - File portable: `dist/DumpAnalyzer-Portable.exe`
     - Gói zip thư mục: `dist/DumpAnalyzer-windows-x64.zip`

4. **Tự động đóng gói trên GitHub Actions:**
   - Dự án tích hợp sẵn GitHub Actions workflow tại `.github/workflows/build.yml`.
   - **Tự động kích hoạt:** Khi push code lên nhánh `main` hoặc gắn tag phiên bản `v*` (ví dụ `git tag v1.5.0 && git push origin v1.5.0`).
   - **Kích hoạt thủ công:** Vào tab **Actions** trên GitHub $\rightarrow$ chọn workflow **"Build & Release DumpAnalyzer"** $\rightarrow$ nhấn **Run workflow**.
   - Cả file `DumpAnalyzer-Portable.exe` và gói zip `DumpAnalyzer-windows-x64.zip` đều được tự động đính kèm vào mục **Artifacts** và **Releases**.

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
```

---

## 5. TÁC GIẢ & BẢN QUYỀN

- **Tác giả phát triển:** **Lilbow**
- **Bản quyền & Mục đích:** Phần mềm mã nguồn mở chuyên dụng phục vụ cộng đồng kỹ thuật viên IT, quản trị viên hệ thống chẩn đoán tự động sự cố sập nguồn và màn hình xanh (BSOD) trên Windows.
