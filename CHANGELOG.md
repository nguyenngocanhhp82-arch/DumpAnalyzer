# NHẬT KÝ THAY ĐỔI (CHANGELOG) — DumpAnalyzer

Mọi thay đổi quan trọng của dự án DumpAnalyzer được ghi lại tại tài liệu này theo từng phiên bản và ngày tháng thực hiện.

## [v1.0.1] - 2026-11-03

### Đợt Cập nhật 02 — Sửa lỗi toàn diện & Ổn định hóa hệ thống
- **Nhóm A (Scorer & Rules):**
  - Sửa tính điểm WHEA: thống nhất `kind="eventlog"` và chia sẻ hàm tính điểm `compute_event_points` giữa phân tích đơn vụ sập và đa vụ sập.
  - Áp dụng thuộc tính `cap` trong `event_rules.yaml` giới hạn điểm tối đa của từng quy tắc cho một đối tượng nghi vấn, tránh thổi phồng điểm số khi sự kiện lặp lại nhiều lần.
  - Bổ sung import `json` còn thiếu trong `correlator.py`.
  - Chuẩn hoá các điều kiện pattern (`ms_core_modules` kiểm tra module Microsoft qua CDB dump, `driver_of_module` map sang hardware type, kiểm tra khoảng ngày `within_days`, yêu cầu `no_dump: true` cho crash không dump).
- **Nhóm B (Parser & Crash Time Source):**
  - Chuẩn hoá offset nhị phân header kernel dump `PAGEDU64` theo chuẩn cấu trúc Microsoft `_DUMP_HEADER64`: BugCheckCode tại `0x38`, DumpType tại `0xF98`, SystemTime (FILETIME 64-bit) tại `0xFA8`, SystemUpTime tại `0xFF8`.
  - Minidump `MINIDUMP_HEADER`: đọc chính xác `TimeDateStamp` tại offset `0x14`.
  - Bổ sung trường `crash_time_source` (`header`, `mtime`, `cdb`, `eventlog_6008`, `estimated`, `kp41`) và `uptime_seconds` vào dataclass `Crash` và `DumpHeaderInfo`.
  - Hiển thị "Nguồn thời điểm" trên giao diện chi tiết GUI (`tab_detail.py`) và CLI.
  - Tự động di chuyển schema SQLite tương thích ngược cho DB cũ (`ALTER TABLE crash ADD COLUMN crash_time_source`, `suspect_driver`).
- **Nhóm C (PowerShell Event Log & Debug):**
  - Viết lại câu lệnh PowerShell dùng `Get-WinEvent -FilterHashtable` + pipeline `ForEach-Object` + `[Console]::OutputEncoding = UTF8`.
  - Xử lý 3 trạng thái: mảng rỗng sạch `[]` khi không có event, ghi log cảnh báo WARNING với stderr khi lỗi PowerShell, và ghi log WARNING kèm số giây khi bị timeout.
  - Bổ sung cấu hình `eventlog_timeout_seconds: 120` trong `settings.yaml` và `DEFAULT_SETTINGS`.
  - Bổ sung cờ `--debug-ps` trong lệnh CLI `dumpanalyzer events`.
- **Nhóm D (Giờ sập cho crash log_only):**
  - Ước tính thời điểm sập hệ thống theo thứ tự ưu tiên: Event 6008 shutdown time -> sự kiện cuối cùng trước khi khởi động lại -> fallback thời điểm Event 41.
  - Mở rộng cửa sổ tương quan cho crash `log_only` thành `[crash_time - window, reboot_time (Event 41) + 2 min]`.
- **Nhóm E (Event 1001 độc lập ngôn ngữ):**
  - Trích xuất mã Bug Check, 4 tham số và đường dẫn file dump trực tiếp từ XML `EventData` (`param1`, `param2`) không phụ thuộc ngôn ngữ hiển thị của Windows.
  - Giữ regex message tiếng Anh làm phương án dự phòng.
  - Lọc Provider cho Event 1001 (chỉ nhận WER-SystemErrorReporting hoặc BugCheck).
- **Nhóm F (Dọn dẹp thiết kế nhỏ):**
  - Bổ sung cột `suspect_driver` trong bảng `crash`, scorer ưu tiên cột này trước khi fallback sang chuỗi cdb thô.
  - Kiểm tra an toàn trước khi copy dump lớn: kiểm tra `max_copy_gb` (mặc định 8 GB) và kiểm tra ổ đĩa trống (cần $\ge 1.2 \times \text{size}$); nếu không đủ thì phân tích trực tiếp file gốc ở chế độ chỉ đọc.
  - Bổ sung thuật toán `calculate_fast_hash` (kích thước + mtime + sha256 1MB đầu + 1MB cuối) làm khoá cache cho file dump lớn.
  - Đảm bảo `.gitignore` và `DumpAnalyzer.spec` / `build_exe.py` loại trừ hoàn toàn `data/*.db`, `workspace/`, `logs/`.

---

## [v1.0.0] - 2026-10-29
 
### Phát hành chính thức: Hoàn thành Toàn diện Dự án DumpAnalyzer (Phases 0–6)

- **Module Phân tích theo lô Đa máy & Fleet Analysis (`analyzer/batch.py` & `engine/batch_analyzer.py`):**
  - Tự động quét cấu trúc thư mục con: mỗi thư mục con tương ứng với một máy tính (hostname / PC Name) hoặc xử lý file dump tại thư mục gốc.
  - Phân tích và chấm điểm độc lập cho từng máy tính qua `score_machine_crashes` và `generate_machine_finding`.
  - Tổng hợp tương quan liên máy (Cross-machine correlation): phát hiện driver lỗi xuất hiện đồng loạt trên nhiều máy tính khác nhau trong công ty (`widespread_drivers`), cảnh báo mức độ nghiêm trọng.
  - Thống kê tỷ lệ lỗi theo dòng máy / model bo mạch chủ và bảng xếp hạng các mã Bug Check phổ biến nhất toàn công ty.
  - Xuất báo cáo tổng hợp đội máy tính (Fleet Overview Report) dạng HTML độc lập (`export_fleet_html`) và Excel đa bảng tính 4 sheets (`export_fleet_excel`).
- **Giao diện Dòng lệnh CLI Mở rộng:**
  - Bổ sung lệnh `dumpanalyzer batch`: Hỗ trợ tham số `--dir`, `--report-html`, `--report-excel`, `--json`.
  - Báo cáo tổng hợp số liệu trực quan trên console, cảnh báo driver diện rộng cho quản trị viên IT.
- **Hệ thống Đóng gói PyInstaller Chuẩn hóa:**
  - File cấu hình PyInstaller spec: `DumpAnalyzer.spec` hỗ trợ cấu hình `--onedir`, `--windowed`, `--uac-admin`.
  - Cập nhật `dumpanalyzer.core.config.get_project_root()` nhận diện môi trường `sys.frozen` để tự động nạp thư mục `config/` đặt ngay cạnh file `.exe`.
  - Giữ nguyên thư mục `config/` bên cạnh file `.exe`, không nhúng ngầm bên trong binary, cho phép nhân viên IT mở sửa các file YAML trực tiếp mà không cần build lại.
  - Không nhúng `cdb.exe` (đảm bảo tính pháp lý phân phối và duy trì cơ chế fallback `header_only` / `log_only`).
  - Viết script tự động hóa `scripts/build_exe.py` và batch script `build_exe.bat` đóng gói một cú nhấp đúp trên Windows.
- **Bộ Tài liệu Bàn giao Chuyên nghiệp:**
  - `docs/RULES_GUIDE.md`: Cẩm nang hướng dẫn chi tiết bằng tiếng Việt cách quản trị, thêm sửa quy tắc (Bugcheck, Driver map, Event rules, Patterns) và kiểm tra bằng `dumpanalyzer validate-rules`.
  - `docs/TESTING_WITH_NOTMYFAULT.md`: Hướng dẫn kiểm thử an toàn các kịch bản crash bằng NotMyFault của Microsoft Sysinternals (High IRQL fault, Buffer overflow, Code overwrite, Hang, Event 41 không dump).
  - Cập nhật hoàn chỉnh `README.md`: Hướng dẫn chạy nhanh một cú nhấp, danh mục lệnh CLI, hướng dẫn đóng gói và thiết lập ngoại lệ diệt virus Windows Defender.
- **Kiểm thử tự động:**
  - Thêm `tests/test_batch.py` và `test_cli_batch` trong `tests/test_cli.py`.
  - Toàn bộ **85/85 tests PASSED (100%)**.

---

## [v0.5.0] - 2026-10-29

### Hoàn thành Phase 5 (Giao diện đồ họa PySide6 & Xuất Báo cáo)
- **Module xuất báo cáo chẩn đoán (`report/exporter.py`):**
  - Xuất báo cáo HTML độc lập (`export_html_report`), nhúng sẵn CSS hiện đại, tương thích in ấn (`@media print`), hiển thị đầy đủ thông tin máy, thẻ KPI, thanh tiến độ xác suất, giải thích nguyên nhân, khuyến nghị phân tầng từ dễ đến khó và bảng bằng chứng.
  - Xuất báo cáo Excel đa bảng tính (`export_excel_report`) với 3 sheet: "Tổng quan & Kết luận", "Danh sách Crash", "Bằng chứng thu thập".
- **Hệ thống giao diện đồ họa chuyên nghiệp PySide6 (`gui/`):**
  - Khung giao diện chuẩn mực (`main_window.py`): Tiêu đề "DumpAnalyzer – Phân tích màn hình xanh & khởi động lại", bộ chọn nguồn dữ liệu (máy cục bộ / thư mục dump), bộ lọc khoảng ngày (Từ - Đến), nút "Phân tích" nổi bật, nút "Huỷ" và nút "Xuất báo cáo".
  - Chạy ngầm đa luồng (`worker.py` - `AnalysisWorker`): Sử dụng `QThread`, cập nhật tiến trình 0-100% kèm thông điệp tiếng Việt, hỗ trợ nút Huỷ an toàn mà không bao giờ làm treo đơ giao diện.
  - **Tab 1: Tổng quan (`tab_overview.py`):** 4 thẻ KPI (Tổng số sự cố, Dump đã phân tích, Nghi ngờ chính, Độ tin cậy), ô tìm kiếm nhanh, bảng danh sách crash với nhãn chữ kèm màu sắc chuyên nghiệp, gắn nhãn rõ ràng **"Không có dump"** cho các phiên `log_only`, hỗ trợ nhấp đúp để xem chi tiết.
  - **Tab 2: Chi tiết crash (`tab_detail.py`):** Bóc tách chuyên sâu từng lần sập: metadata dump, 4 tham số Bug Check (`P1..P4`), khung xem Call Stack (`STACK_TEXT`) với font monospaced dễ đọc, và bảng sự kiện Event Log trong cửa sổ 10 phút trước crash.
  - **Tab 3: Kết luận (`tab_verdict.py`):** Xếp hạng xác suất nguyên nhân với thanh phần trăm trực quan, phân tích mức độ tin cậy, cảnh báo mâu thuẫn giữa Dump và Event Log, giải thích nguyên nhân bằng tiếng Việt trung thực, danh sách hành động khuyến nghị phân tầng độ khó (Tầng 1: Dễ -> Tầng 4: Phức tạp) và các nút xuất báo cáo trực tiếp.
  - **Tab 4: Cài đặt & Khả năng ghi dump (`tab_settings.py`):**
    - Mục "Khả năng ghi dump": Bảng kết quả kiểm tra `CrashControl`, RAM, dung lượng trống ổ C:, pagefile, sự kiện `volmgr` 161/162, huy hiệu trạng thái (SẴN SÀNG / CẦN CHÚ Ý / KHÔNG GHI ĐƯỢC DUMP).
    - Nút "Bật tự động ghi dump (Automatic dump)": Có hộp thoại xác nhận cảnh báo sửa registry `CrashDumpEnabled = 7` và tự động lưu file backup `.reg`.
    - Mục "Cấu hình phân tích": Đường dẫn `cdb.exe`, Microsoft Symbol Server, thư mục workspace, cửa sổ thời gian và số luồng song song.
    - Mục "Quản lý quy tắc": Nút kiểm tra tính hợp lệ toàn diện (Validate Rules) và nút mở thư mục `config/rules/`.
- **Bộ kiểm thử tự động toàn diện:**
  - Bổ sung `tests/test_report.py` (3 tests) và `tests/test_gui.py` (6 tests).
  - Toàn bộ **81/81 tests PASSED (100%)** trong 2.12s ở môi trường headless.

---

## [v0.4.0] - 2026-10-29

### Hoàn thành Phase 4 (Rule Engine: Chấm điểm & Kết luận)
- **Module nạp và kiểm tra tính hợp lệ của bộ luật (`rule_loader.py`):**
  - Chuẩn hoá mã Bug Check (hỗ trợ `0x124`, `124`, `0x00000124` về dạng chuẩn `0x124`).
  - Tải toàn bộ cấu hình YAML: `bugcheck_rules.yaml`, `driver_map.yaml`, `event_rules.yaml`, `patterns.yaml`, `settings.yaml`.
  - Kiểm tra cú pháp YAML nghiêm ngặt: thông báo chính xác số dòng, số cột và giải thích lỗi nếu file cấu hình bị sai cú pháp.
  - Kiểm tra ngữ nghĩa cấu hình: phát hiện mã lỗi trùng lặp, thiếu trường bắt buộc (`priors`, `actions`, `thresholds`...), trọng số không hợp lệ.
  - Bổ sung hàm `validate_rules_and_settings()` cho phép kiểm tra toàn diện trước khi khởi chạy.
- **Mở rộng bộ luật chẩn đoán chuẩn (`bugcheck_rules.yaml` & `driver_map.yaml`):**
  - Mở rộng thêm 16 mã Bug Check phổ biến (0x1E, 0xEF, 0x139, 0x101, 0x7A, 0xF4, 0x24, 0x23, 0x4E, 0xC2, 0xC4, 0xC9, 0x117, 0x119, 0x12E và 0x0 uncommanded power off/freeze).
  - Bổ sung ánh xạ CPU hardware driver trong `driver_map.yaml` (`authenticamd.sys`, `genuineintel.sys` -> type: `cpu`).
- **Bộ máy chấm điểm giả thuyết (`scorer.py`):**
  - `score_single_crash()`: Chấm điểm từng phiên crash:
    - Bắt đầu từ xác suất tiên nghiệm (prior) của mã Bug Check.
    - Phân định rõ driver bên thứ ba theo thiết bị (GPU, CPU, Storage, Network, Antivirus...), cộng điểm trực tiếp vào nhóm thiết bị tương ứng mà không phân mảnh điểm số.
    - Áp dụng hệ số đồng thuận (consensus factor 1.5x) khi bằng chứng Event Log (nvlddmkm, WHEA, Disk, stornvme...) khớp với giả thuyết từ dump.
    - Chuẩn hoá điểm theo thang phần trăm (0 - 100%).
    - Áp dụng các trần độ tin cậy nghiêm ngặt:
      - 1 crash đơn lẻ: trần tối đa mức "trung bình" (< 70%).
      - `header_only` (không có cdb.exe): trần tối đa "trung bình".
      - `log_only` có sự kiện bổ trợ (WHEA, Disk...): trần tối đa "trung bình".
      - `log_only` không có sự kiện bổ trợ hoặc BugCheck 0 (mất nguồn): độ tin cậy "thấp" (< 40%).
      - Quy tắc vàng `log_only`: Chỉ được kết luận về nhóm thiết bị phần cứng hoặc sự cố nguồn, tuyệt đối không quy trách nhiệm cho một file driver cụ thể.
  - `score_machine_crashes()`: Tổng hợp chẩn đoán trên toàn máy:
    - Tổng hợp điểm của từng giả thuyết qua các crash (crash `log_only` tính trọng số 0.5 để không lấn át dump thực sự).
    - Áp dụng mẫu hình đa crash từ `patterns.yaml`:
      - Nhiều crash cùng driver bên thứ ba: điểm thưởng lặp lại (repeat bonus 1.25x khi xuất hiện >= 3 lần), cho phép đạt mức tin cậy "cao" (>= 70%).
      - Nhiều crash khác nhau nhưng cùng đổ lỗi cho các module hệ thống Microsoft khác nhau (`ntoskrnl.exe`, `win32kbase.sys`, `hal.dll`...): nghi vấn lỗi phần cứng chung (RAM/CPU/Mainboard).
    - Phát hiện mâu thuẫn (conflict detection): cảnh báo rõ khi giả thuyết từ dump và giả thuyết từ Event Log xung đột mà chênh lệch điểm < 15%.
- **Bộ máy kết luận & khuyến nghị hành động (`verdict.py`):**
  - Phân loại hành động tiếp theo theo độ khó tăng dần (`sort_next_steps_easy_to_hard`):
    - Tầng 1 (Dễ nhất): Kiểm tra phần mềm, nhiệt độ, kiểm tra cấu hình ghi dump.
    - Tầng 2 (Trung bình): Gỡ driver bằng DDU và cài mới, chkdsk, SFC /scannow.
    - Tầng 3 (Nâng cao): Kiểm tra phần cứng chuyên sâu, MemTest86, kiểm tra cáp ổ cứng/nguồn.
    - Tầng 4 (Phức tạp nhất): Cập nhật BIOS bo mạch chủ, thay thế linh kiện (PSU, RAM, ổ cứng).
  - Tự động sinh báo cáo kết luận finding bằng tiếng Việt giải thích rõ ràng cho nhân viên IT, liên kết với các ID bằng chứng cụ thể.
  - Lưu kết luận vào CSDL bảng `finding` qua các hàm `insert_finding()`, `get_findings_by_crash()`, `get_findings_by_machine()`.
- **Giao diện dòng lệnh (`cli.py`):**
  - Bổ sung lệnh `dumpanalyzer validate-rules`.
  - Bổ sung lệnh `dumpanalyzer verdict [--crash-id <id>] [--all-machine]`.
- **Bộ kiểm thử tự động toàn diện:**
  - Bổ sung `tests/test_rule_loader.py` (8 tests), `tests/test_scorer.py` (9 tests), `tests/test_verdict.py` (5 tests).
  - Toàn bộ **72/72 tests PASSED (100%)**.

---

## [v0.3.0] - 2026-10-29

### Hoàn thành Phase 3 (Mở rộng Nguồn dữ liệu & Tương quan)
- **Module phân tích sự kiện Windows Event Log (`eventlog.py`):**
  - Trích xuất thông tin chi tiết từ XML (`parse_event_xml`): Provider, EventID, Level, TimeCreated (UTC), EventData theo cấu trúc key-value.
  - Xử lý đặc thù cho Event 41 (Kernel-Power): bóc tách `BugcheckCode` thập phân chuyển sang Hex (ví dụ 278 -> `0x116`; 0 -> `0x0` biểu thị mất nguồn/treo cứng đột ngột không qua BSOD).
  - Phân tích cú pháp mô tả Event 1001 (WER / BugCheck): bóc tách mã lỗi, 4 tham số và đường dẫn dump file đã ghi.
  - Hỗ trợ truy vấn PowerShell `Get-WinEvent` với các bộ lọc Provider/Event ID trọng yếu (Kernel-Power, WHEA-Logger, Disk, nvlddmkm/Display, stornvme, volmgr...).
- **Module thu thập thông tin phần cứng & hệ thống (`hardware.py`):**
  - `collect_machine_info()`: Thu thập CPU, RAM, GPU, Model bo mạch chủ, BIOS version, OS build, Anti-virus đang hoạt động.
  - `collect_smart_status()`: Đọc trạng thái ổ cứng vật lý và SMART.
- **Module thu thập Driver bên thứ ba & Lịch sử cập nhật (`drivers_updates.py`):**
  - `collect_third_party_drivers()`: Lấy danh sách driver không phải của Microsoft kèm ngày cài đặt/phiên bản.
  - `collect_recent_windows_updates()`: Thu thập danh sách bản cập nhật Windows (KB) và driver được cài đặt trong 30 ngày gần nhất.
- **Engine tương quan dữ liệu (`correlator.py`):**
  - Cửa sổ thời gian 10 phút trước crash: gom các cảnh báo ổ đĩa (Disk/stornvme/storahci), driver sập (nvlddmkm), cảnh báo phần cứng WHEA để làm bằng chứng liên đới.
  - Hợp nhất Event 41 và Event 1001 thành 1 phiên crash duy nhất nếu chúng xảy ra cùng thời điểm.
  - Tự động sinh bản ghi Crash dạng `analyzed_by = 'log_only'` cho các sự cố tắt đột ngột hoặc BSOD không sinh được file dump.
  - Tương quan cập nhật Windows/Driver trong vòng 7 ngày trước crash.
  - Lưu và liên kết Evidence vào cơ sở dữ liệu SQLite (`evidence` table).
- **Cập nhật CSDL & Dòng lệnh (`db.py`, `cli.py`):**
  - Thêm các hàm `insert_machine()`, `insert_evidence()`, `get_evidences_by_crash()`.
  - Bổ sung subcommand `dumpanalyzer events [--from] [--to]`.
- **Bộ Fixtures & Unit Tests:**
  - Bổ sung `tests/fixtures/sample_events.json`.
  - Thêm 7 unit tests mới trong `tests/test_eventlog.py` và `tests/test_correlator.py`, nâng tổng số test lên **50/50 PASSED (100%)**.

---

## [v0.2.0] - 2026-10-29

### Hoàn thành Phase 2 (Tích hợp cdb.exe: Phân tích sâu)
- **Module phân tích cú pháp cdb (`cdb_parser.py`):**
  - Regex bóc tách toàn diện các trường từ output `!analyze -v`: `BUGCHECK_CODE`, `BUGCHECK_P1..P4`, `IMAGE_NAME`, `MODULE_NAME`, `PROCESS_NAME`, `FAILURE_BUCKET_ID`, `STACK_TEXT`.
  - Phân định rõ Nạn nhân vs Thủ phạm: Bổ sung danh sách `DEFAULT_MS_CORE_MODULES` (bao gồm cả `nt`, `ntoskrnl.exe`, `hal.dll`, `win32k*.sys`, `ntfs.sys`...). Nếu `IMAGE_NAME` là module Microsoft, tự động quét tìm và chỉ định driver bên thứ ba đầu tiên trong call stack làm nghi vấn chính.
  - Bóc tách thông tin hệ điều hành (`vertarget`), thời điểm sập (`.time`), thời gian chạy (`System Uptime`) và danh sách module nạp kèm địa chỉ (`lm t n`).
- **Module điều phối cdb ngầm (`cdb_runner.py`):**
  - Thực thi `cdb.exe` qua danh sách đối số an toàn trong `subprocess.run`, không ghép chuỗi shell.
  - Kiểm soát `timeout` chặt chẽ (mặc định 300 giây).
  - Tự động bổ sung lệnh chuyên biệt theo mã lỗi (`extra_cdb` từ YAML):
    - `0x124`: `!errrec {p2}`
    - `0x133`: `!dpcs`, `!timer`
    - `0xD1`, `0xA`, `0xC4`: `!irp`, `!devstack`
    - `0x1A`, `0x50`, `0xC2`: `!vm`, `!poolused 2`
  - Cơ chế **Fallback an toàn về `header_only`**: Nếu thiếu `cdb.exe`, cdb bị timeout hoặc symbol lỗi, hệ thống tự động giữ nguyên thông tin header và đánh dấu rõ `analyzed_by = 'header_only'`, không làm sập chương trình.
  - Phân tích song song nhiều dump qua `ThreadPoolExecutor` (mặc định 2 luồng).
  - Hàm `warmup_symbols()`: Tải trước Symbol Microsoft để tránh nghẽn mạng khi phân tích hàng loạt.
- **Cập nhật CSDL & Dòng lệnh (`db.py`, `cli.py`):**
  - Lưu toàn bộ `cdb_raw_output` vào SQLite để phục vụ re-score sau này.
  - Thêm subcommand `dumpanalyzer analyze [--all] [--path] [--concurrency]`.
  - Thêm subcommand `dumpanalyzer warmup-symbols`.
- **Bộ Fixtures & Unit Tests:**
  - Tạo 10 file output `!analyze -v` mẫu trong `tests/fixtures/cdb_outputs/` mô phỏng đầy đủ các ca (WHEA CPU, GPU NVIDIA, card mạng Realtek, Antivirus Kaspersky trong ntoskrnl, SSD NVMe, lỗi phần cứng RAM thuần tuý, thiếu symbol, timeout).
  - Thêm 15 bài test mới, nâng tổng bộ kiểm thử lên **43/43 PASSED (100%)**.

---

## [v0.1.2] - 2026-10-29

### Hoàn thành Phase 1B (Kiểm tra & Cấu hình Khả năng ghi Dump)
- **Module kiểm tra cấu hình (`dump_config.py`):**
  - Đọc registry `CrashControl`: `CrashDumpEnabled`, `AutoReboot`, `Overwrite`, `MinidumpDir`, `DumpFile`.
  - Kiểm tra tình trạng Pagefile trên ổ hệ thống (C:), cảnh báo nếu thiếu pagefile.
  - Kiểm tra dung lượng trống ổ C: so với RAM vật lý (ngưỡng an toàn: RAM + 5GB).
  - Quét sự kiện dịch vụ ghi dump `volmgr` Event 161 (thất bại) và 162 (thành công).
  - Hàm `evaluate_readiness()`: Phân loại 3 mức trạng thái **SẴN SÀNG / CẦN CHÚ Ý / KHÔNG GHI ĐƯỢC DUMP** kèm nguyên nhân và khuyến nghị xử lý bằng tiếng Việt.
  - Cơ chế áp dụng an toàn (`apply_automatic_dump`):
    - Tự động xuất file sao lưu registry cũ ra `backup/CrashControl_<hostname>_<time>.reg`.
    - Chỉ cho phép sửa khi có cờ `--apply` VÀ người dùng gõ xác nhận trực tiếp (`y`).
    - Chỉ sửa duy nhất `CrashDumpEnabled = 7` (Automatic memory dump), không đụng pagefile hay các khoá khác, không tự khởi động lại máy.
- **Cập nhật dòng lệnh (`cli.py`):**
  - Bổ sung subcommand `dumpanalyzer check-dump-config [--apply]`.
- **Kiểm thử tự động:**
  - Tạo `tests/test_dump_config.py` với 6 test case kiểm tra đánh giá trạng thái, định dạng file sao lưu .reg, huỷ bỏ an toàn khi chưa xác nhận và lệnh CLI.
  - Tổng số test tự động đạt **28/28 PASSED (100%)**.

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
