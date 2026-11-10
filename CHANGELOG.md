# NHẬT KÝ THAY ĐỔI (CHANGELOG) — DumpAnalyzer

Mọi thay đổi quan trọng của dự án DumpAnalyzer được ghi lại tại tài liệu này theo từng phiên bản và ngày tháng thực hiện.

## [v1.5.1] - 2026-11-10

### Khắc Phục Triệt Để Lỗi Đọc Windows Event Log Qua PowerShell
- **Sửa lỗi `There is not an event provider on the localhost computer that matches "WindowsUpdateClient"` (và các provider tùy chọn như `nvlddmkm`, `storahci`, `WER-SystemErrorReporting`, `MsiInstaller`):**
  - Trong `src/dumpanalyzer/analyzer/eventlog_analyzer.py` (`build_harvest_script`): Loại bỏ lọc cứng theo danh sách `ProviderName` gộp chung; tách riêng các bộ lọc từng kênh (`System`, `Application`) và lọc theo `Id` thông tin thiết yếu (`12, 19, 20, 41, 1001, 1074, 6005, 6006, 6008` trên `System`; `1001, 1033, 11707` trên `Application`).
  - Trong `src/dumpanalyzer/collectors/eventlog.py` (`build_eventlog_script`): Tách truy vấn thành từng Provider riêng biệt trong vòng lặp `try/catch` để không vượt trần ~25 điều kiện XPath của `EvtQuery` và tự động bỏ qua các provider không tồn tại trên máy cục bộ.
  - Khắc phục lỗi khi 1 bộ lọc con không có sự kiện (`NoMatchingEventsFound`) gây sập toàn bộ các bộ lọc còn lại trả về rỗng `[]`.
- **Vượt qua giới hạn 2 MB `MaxJsonLength` của PowerShell 5.1 & Chống lỗi Resource DLL:**
  - Chuyển sang xuất **NDJSON** (chuyển đổi từng object qua `ForEach-Object { ... | ConvertTo-Json -Depth 4 -Compress }`), cho phép đọc hàng ngàn sự kiện chứa XML đầy đủ mà không bao giờ bị tràn bộ đệm `JavaScriptSerializer`.
  - Bọc `try/catch` bảo vệ khi truy xuất `$_.Message` và `$_.ToXml()` cho từng bản ghi sự kiện.
- **Tiện ích thực thi PowerShell an toàn cho GUI đóng gói (`src/dumpanalyzer/core/ps_runner.py`):**
  - Chạy PowerShell qua `-EncodedCommand` (UTF-16LE Base64) để không bị lỗi escape dấu nháy, xuống dòng hay đường dẫn tiếng Việt chứa dấu cách/ngoặc vuông.
  - Truyền `stdin=subprocess.DEVNULL` và cờ `CREATE_NO_WINDOW` giúp bản đóng gói `console=False` (`DumpAnalyzer-Portable.exe`, `DumpAnalyzer.exe`) không bị lỗi `[WinError 6] The handle is invalid` hay nhấp nháy cửa sổ đen.
  - Tự động loại bỏ ký tự UTF-8 BOM (`\ufeff`) và phân tích linh hoạt cả JSON Array lẫn NDJSON.
  - Áp dụng đồng bộ cho `eventlog_analyzer.py`, `eventlog.py`, `dump_config.py` (`volmgr`) và `windows_memory_diagnostic.py`.
- **Cải thiện giao diện Tab Event Log (`src/dumpanalyzer/gui/tab_eventlog.py`):**
  - Tách rõ nút **"📂 Nhập file .evtx"** và nút **"📁 Nhập thư mục .evtx"** để chọn trực tiếp file hoặc cả thư mục.
  - Sửa bộ lọc danh mục để lọc chính xác theo `category_id` (khắc phục lỗi không khớp tên danh mục `"Màn hình / GPU"`).

## [v1.5.0] - 2026-11-10

### Đóng Gói Thành 1 File Chạy Portable Duy Nhất (`DumpAnalyzer-Portable.exe`)
- **Bản Chạy Portable 1 File Độc Lập Hoàn Toàn (`src/dumpanalyzer/main_portable.py`):**
  - Đóng gói toàn bộ ứng dụng thành 1 file `.exe` duy nhất (`DumpAnalyzer-Portable.exe` / `DumpAnalyzer-Portable`), dung lượng nén tối ưu ~69 MB.
  - Tích hợp sẵn toàn bộ tài nguyên: CSDL SQLite schema (`schema.sql`), cấu hình mặc định `settings.yaml`, 26 quy tắc BSOD, quy tắc Event Log và bộ mã Bug Check chuẩn Microsoft trực tiếp vào file thực thi.
  - Chạy ngay lập tức từ USB cứu hộ hoặc bất kỳ thư mục nào trên máy tính cứu hộ mà không cần cài đặt Python, không cần giải nén thư mục phụ thuộc.
- **Cơ Chế Điều Phối Kép Thông Minh (Dual-Dispatch):**
  - **Chế độ GUI:** Khi nhấp đúp chuột từ File Explorer (không có tham số hoặc có `--gui`/`-g`), khởi động giao diện đồ hoạ PySide6 sắc nét với High DPI scaling, không mở cửa sổ console đen thừa thãi.
  - **Chế độ CLI:** Khi gọi từ Command Prompt / PowerShell với các lệnh con (`scan`, `analyze`, `events`, `check-dump-config`, `selftest`...), tự động gắn kết vào console cha (`AttachConsole(-1)`) và in kết quả trực tiếp ra màn hình terminal.
- **Hệ Thống Phân Tách Đường Dẫn Cấu Hình & Dữ Liệu Bền Vững (`src/dumpanalyzer/core/config.py`):**
  - Bổ sung hàm `get_config_dir()`: Ưu tiên nạp thư mục `config/` đặt bên cạnh file `.exe` nếu IT muốn tùy biến hoặc bổ sung quy tắc mới mà không cần biên dịch lại; nếu không có, tự động fallback sang `config/` tích hợp sẵn trong bundle (`sys._MEIPASS`).
  - Hàm `get_project_root()` luôn trỏ tới thư mục chứa file `.exe`, đảm bảo CSDL SQLite `data/dumpanalyzer.db`, file nhật ký `logs/dumpanalyzer.log`, và workspace phân tích luôn được lưu trữ bền vững bên ngoài, không bị xóa khi tắt ứng dụng.
- **Cập Nhật PyInstaller Spec & Script Đóng Gói (`DumpAnalyzer.spec`, `build_exe.py`):**
  - Bổ sung cấu hình `a_portable` và `exe_portable` vào `DumpAnalyzer.spec` với quyền Administrator (`uac_admin=True`) để đọc trực tiếp `C:\Windows\Minidump`.
  - Giữ nguyên bản đóng gói thư mục (`coll` / `DumpAnalyzer-windows-x64.zip`) cho mục đích sử dụng truyền thống.
  - Tự động kiểm tra và in thông tin chi tiết kích thước file portable sau khi build thành công.
- **Tích Hợp CI/CD GitHub Actions (`.github/workflows/build.yml`):**
  - Tự động kiểm tra tính toàn vẹn của `DumpAnalyzer-Portable.exe` trong pipeline Windows runner.
  - Xuất bản cả file `DumpAnalyzer-Portable.exe` lẫn file zip thư mục `DumpAnalyzer-windows-x64.zip` lên mục Artifacts và GitHub Releases.
- **Sửa Lỗi Format Trợ Giúp CLI (`src/dumpanalyzer/cli.py`):**
  - Sửa ký tự `%` trong trợ giúp subcommand `dump-rollback` (`100%%`) để tránh lỗi `TypeError: %c requires int or char` khi gọi `dumpanalyzer --help`.
- **Bộ Kiểm Thử Đóng Gói (`tests/test_packaging.py`, `tests/test_cli.py`):**
  - Bổ sung các bài test kiểm tra cấu hình `DumpAnalyzer.spec`, cơ chế fallback `get_config_dir()`, điều phối `main_portable.py`, và gọi `--help` an toàn. 100% test pass.

## [v1.4.0] - 2026-11-10

### Đợt Cập nhật 06 — Phân Tích Chuyên Sâu Windows Event Log, Hỗ Trợ File .EVTX Ngoại Vi & Tab Event Log
- **Mô-đun Phân Tích Sự Kiện Chuyên Sâu (`src/dumpanalyzer/analyzer/eventlog_analyzer.py`):**
  - Thu thập theo cấp độ nghiêm trọng: Lấy toàn bộ sự kiện mức Critical (Level 1), Error (Level 2), Warning (Level 3), và các sự kiện Information trọng yếu (Event 41, 6005, 6006, 6008, 1074, 12, 1001, 19, 20).
  - Hỗ trợ đa nguồn dữ liệu: Quét log trực tiếp của máy (System, Application) và nhập tệp hoặc thư mục `.evtx` ngoại vi (từ máy khác, khách hàng gửi, bản sao lưu).
  - Phân tích độc lập với dump: Dựng dòng thời gian (Timeline) sự kiện theo thứ tự tăng dần, thống kê theo cấp độ, nguồn và danh mục nghiệp vụ.
  - Tự động phát hiện bùng phát lỗi đột biến (Spike / Burst Detection): Cảnh báo khi có mật độ lỗi cao bất thường (ví dụ: $\ge 5$ lỗi Disk hoặc driver trong 5 phút).
  - Phân tích ngữ cảnh trước sập nguồn (Pre-Crash Context): Với mỗi lần sập nguồn hoặc tắt máy bất thường (Event 41 / 6008), trích xuất và hiển thị danh sách các sự kiện cảnh báo/lỗi xảy ra trong 15 phút trước đó.
- **Quy Tắc Phân Loại Nghiệp Vụ Trong YAML (`config/rules/event_categories.yaml`):**
  - Định nghĩa 8 nhóm danh mục sự kiện chuẩn hóa: Sập & Khởi động bất thường, Phần cứng (WHEA), Lưu trữ & Hệ thống tệp, USB & Thiết bị ngoại vi, Màn hình & Card đồ họa (GPU), Cập nhật & Cài đặt, Dịch vụ & Ứng dụng, Nguồn & Nhiệt độ.
  - Các ID chưa chắc chắn được đánh dấu rõ ràng `[CẦN XÁC MINH]`. Cho phép kỹ thuật viên IT dễ dàng mở rộng và tinh chỉnh.
  - Tích hợp kiểm tra hợp lệ cấu trúc vào lệnh `dumpanalyzer validate-rules` (`src/dumpanalyzer/engine/rule_loader.py`).
- **Giao Diện Tab "Nhật ký Event Log" Mới (`src/dumpanalyzer/gui/tab_eventlog.py`, `src/dumpanalyzer/gui/main_window.py`):**
  - Bổ sung Tab thứ 3 trong giao diện chính với 5 thẻ KPI thống kê trực quan (Tổng số, Critical, Error, Warning, Đột biến Spikes).
  - Thanh công cụ thao tác nhanh: Quét log máy ngầm (QThread worker không đơ giao diện), nút chọn tệp/thư mục `.evtx`, nút xuất báo cáo Excel (.xlsx), và hộp kiểm che thông tin nhạy cảm.
  - Bộ lọc đa chiều: Lọc thời gian thực theo từ khóa tìm kiếm, cấp độ nghiêm trọng (Level), danh mục nghiệp vụ (Category), và Provider.
  - Bảng danh sách sự kiện kèm huy hiệu (Badge) màu sắc độ tương phản cao và khung xem chi tiết: Thông báo Message, EventData bóc tách, XML thô và Ngữ cảnh trước sập máy.
- **Bảo Mật & Che Chắn Thông Tin Cá Nhân (Privacy Redaction):**
  - Tự động phát hiện và che đường dẫn thư mục người dùng (`C:\Users\[ANONYMIZED_USER]\...`), địa chỉ IPv4 (`[IP_REDACTED]`), và tài khoản `[DOMAIN]\[USER_REDACTED]`.
  - Phân tích và xử lý hoàn toàn cục bộ (offline 100%), không gửi bất kỳ dữ liệu nào ra mạng Internet.
- **Xuất Báo Cáo Excel Đa Bảng Tính (.xlsx):**
  - Sheet 1 "Tổng quan & Thống kê": Thống kê cấp độ, phân bố danh mục, danh sách đợt bùng phát lỗi (Spikes), và ngữ cảnh trước sập nguồn (Pre-Crash).
  - Sheet 2 "Danh sách Sự kiện": Chi tiết từng sự kiện với thời gian Local, UTC, Mức độ, Danh mục, Nguồn, ID, Kênh và dữ liệu EventData.
- **Mở Rộng Dòng Lệnh CLI (`src/dumpanalyzer/cli.py`):**
  - Bổ sung các tham số mới cho lệnh `dumpanalyzer events`: `--evtx <path>`, `--export-excel <file.xlsx>`, `--redact`, `--spikes`, `--pre-crash`.
- **Tích Hợp Luồng Chấm Điểm & Kiểm Thử Toàn Diện:**
  - Tích hợp kết quả phân tích sự kiện vào luồng `pipeline.py`. Các sự kiện có luật trong `event_rules.yaml` sinh bằng chứng chấm điểm; các sự kiện chưa có luật chỉ hiển thị phân tích, không cộng điểm bừa bãi.
  - Bổ sung bộ kiểm thử `tests/test_eventlog_analyzer.py` đạt 100% PASS. Toàn bộ 205/206 tests của dự án đạt PASS (1 skip an toàn).

### Đợt Cập nhật 05 — Bộ Đọc Minidump Triage Nội Bộ Thuần Python & Tái Thiết Kế Giao Diện
- **Bộ Đọc Minidump Triage Thuần Python (`src/dumpanalyzer/analyzer/triage_reader.py`):**
  - Đọc trực tiếp cấu trúc nhị phân `PAGEDU64` của Minidump Triage (DumpType = 4) không phụ thuộc `cdb.exe`, WinDbg hay Symbol server Microsoft.
  - Trích xuất tự động: Header (OS build, BugCheck code, 4 params, giờ sập UTC từ SystemTime `0xFA8`), Context (RIP, RSP), Ngoại lệ (Exception Code, Exception Address, Module, ý nghĩa ngoại lệ), Call stack modules theo thứ tự, và danh sách driver đã bị gỡ trước khi sập (Unloaded drivers).
  - Tuân thủ nghiêm ngặt 10 nguyên tắc kỹ thuật N1-N10: chịu lỗi không crash, không đọc/lưu dữ liệu bộ nhớ người dùng vào CSDL, phân biệt rõ ràng giữa kết quả đã kiểm chứng và chưa kiểm chứng.
- **Phân Loại Module Hệ Thống (`src/dumpanalyzer/engine/module_classifier.py`, `config/rules/module_classes.yaml`):**
  - Phân loại chính xác các họ driver: `ms_inbox` (driver chuẩn Microsoft đi kèm Windows), `fs_stack` (ngăn xếp hệ thống tệp), `usb_storage_driver` (USB mass storage: USBSTOR.SYS, uaspstor.sys), `third_party_filter_known`.
  - Không phân biệt chữ hoa/chữ thường, ngăn ngừa gán nhãn sai driver Microsoft (như `fastfat.SYS`) làm thủ phạm phần cứng đơn lẻ.
- **Luật Bằng Chứng Triage & Tích Hợp Chẩn Đoán (`src/dumpanalyzer/engine/triage_evaluator.py`, `config/rules/triage_rules.yaml`):**
  - Đánh giá tự động 5 luật bằng chứng triage: `fs_path_all_microsoft` (chuỗi xử lý chỉ có driver Microsoft), `usb_mass_storage_active`, `usb_mass_storage_churn` (driver USB bị gỡ đột ngột), `third_party_filter_in_stack`, `null_dereference_info`.
  - Cập nhật quy tắc BugCheck `0x23` (`FAT_FILE_SYSTEM`): phân bổ trọng số hợp lý cho nhóm `storage` (50) và `usb_peripheral` (25).
- **Mở Rộng CSDL SQLite & Tự Động Di Trú (Migration):**
  - Bổ sung 4 cột mới vào bảng `crash`: `exception_code`, `exception_address`, `exception_module`, `triage_json`.
  - Cơ chế tự động kiểm tra và thêm cột nếu CSDL cũ đã tồn tại, đảm bảo tương thích ngược 100%.
- **Công Cụ Dòng Lệnh CLI Mới (`src/dumpanalyzer/cli.py`):**
  - `dumpanalyzer triage-info <dump_path> [--json]`: Đọc và hiển thị cấu trúc chi tiết minidump triage thuần Python.
  - `dumpanalyzer triage-compare <dump_path>`: Đối chiếu từng trường giữa bộ đọc triage nội bộ và WinDbg `cdb.exe`.
  - Bổ sung kiểm tra tự động `triage_reader` vào lệnh `dumpanalyzer selftest`.
- **Tái Thiết Kế Toàn Diện Giao Diện Người Dùng (UI Redesign):**
  - **Tab "Chi tiết Crash" (`src/dumpanalyzer/gui/tab_detail.py`):**
    - Thay thế bảng grid 11 trường chật chội cũ bằng 4 Thẻ Card bo góc hiện đại: (1) Tổng quan BugCheck với mã lỗi lớn nổi bật; (2) 4 Tham số BugCheck dạng badge 2x2 tinh tế, dễ đọc; (3) Khối Bằng chứng Minidump Triage (ngoại lệ, địa chỉ, chuỗi module stack); (4) Chi tiết kỹ thuật & tệp dump.
  - **Tab "Cài đặt" (`src/dumpanalyzer/gui/tab_settings.py`):**
    - Khắc phục triệt để lỗi chữ đè, chồng lên nhau: chuyển các dòng chú thích xuống dưới ô chọn, thiết lập word-wrap tự nhiên.
    - Bảng thông số CrashControl co giãn tự nhiên không bị cắt cụt.
    - Thêm tùy chọn bật/tắt bộ đọc Triage nội bộ (`triage_reader.enabled`).
    - Bố cục thẻ Thông tin phần mềm gọn gàng, tôn vinh tác giả phát triển **Lilbow**.
- **Bộ Kiểm Thử Toàn Diện:**
  - Bổ sung 4 file test mới: `test_triage_reader.py`, `test_module_classes.py`, `test_triage_rules.py`, `test_triage_real_sample.py`.
  - Đạt 197/198 tests passed (1 skip file dump thật nếu không có trong private_fixtures).

---

## [v1.2.1] - 2026-11-04

### Bản vá HOTFIX 03 — Sửa lỗi luồng phân tích GUI & Chuẩn hóa Pipeline Tập trung
- **Chuẩn hóa Bộ tìm kiếm Dump (`src/dumpanalyzer/collectors/dump_finder.py`):**
  - Khắc phục triệt để lỗi `'WindowsPath' object is not iterable` (hoặc `PosixPath` trên Linux) khi truyền đối tượng `Path` hoặc `str` đơn lẻ vào `find_dumps`.
  - Tự động bọc tham số `search_paths` thành `[search_paths]` nếu là `str` hoặc `os.PathLike`.
  - Ngăn ngừa duyệt từng ký tự chuỗi đường dẫn gây quét nhầm toàn bộ ổ đĩa gốc và phát sinh lỗi quyền truy cập.
- **Tách Pipeline Phân tích Tập trung (`src/dumpanalyzer/engine/pipeline.py`):**
  - Xây dựng module mới `run_analysis(...)` chuẩn hoá toàn bộ luồng phân tích đầu-cuối: quét dump, nạp cache CSDL SQLite, trích xuất cdb/header, thu thập Windows Event Log và lịch sử cập nhật Windows, tổng hợp bằng chứng, tính toán điểm nghi ngờ và sinh kết luận Finding.
  - Đảm bảo tính nhất quán 100% giữa giao diện đồ hoạ GUI và dòng lệnh CLI.
  - Sửa toàn diện 5 điểm gọi sai trong pipeline:
    1. Dump collection: truyền danh sách `[folder_path]` / danh sách đường dẫn hợp lệ.
    2. Truy cập kết quả `find_dumps`: coi kết quả là dictionary và truy xuất `item["path"]` (đối tượng `Path`), không dùng trực tiếp thuộc tính của dict.
    3. Tương quan cập nhật Windows: gọi `correlator.correlate_recent_updates(crashes, updates)` 1 lần duy nhất cho toàn bộ danh sách crash thay vì gọi lặp trong vòng lặp từng crash.
    4. Chấm điểm sự cố máy: gọi `score_machine_crashes(crashes_with_evs, rules, settings)` với danh sách tuple `[(Crash, List[Evidence])]` và trả về kết quả chấm điểm có cấu trúc.
    5. Sinh kết luận: gọi `generate_machine_finding(machine_id, scored_result, rules)` đúng chữ ký hàm engine.
  - Xử lý êm thuận khi không tìm thấy file dump nào trên máy: trả về Finding mức `"không đủ dữ kiện"` kèm thông điệp tiếng Việt thân thiện, không ném ngoại lệ.
- **Tái cấu trúc Luồng GUI Worker & Cải tiến Báo lỗi (`src/dumpanalyzer/gui/worker.py`, `src/dumpanalyzer/gui/main_window.py`):**
  - `AnalysisWorker` ủy quyền toàn bộ cho `run_analysis`, đồng bộ hoá thanh tiến trình và thông báo trạng thái qua callback.
  - Hỗ trợ kiểm tra cờ huỷ an toàn `_is_cancelled` ngay từ bước 0 và xuyên suốt pipeline.
  - Tín hiệu lỗi `error = Signal(str, str)` chuyển đầy đủ tóm tắt lỗi có tên loại lỗi `(TênLoạiLỗi)` và chi tiết kỹ thuật (`traceback`).
  - Hộp thoại báo lỗi của `MainWindow` hiển thị chi tiết kỹ thuật có thể mở rộng (collapsible detailed text), đường dẫn file log `logs/dumpanalyzer.log`, và nút chức năng **Sao chép chi tiết** để người dùng dễ dàng báo cáo cho bộ phận phát triển.
- **Bộ Kiểm thử Tự động Bổ sung:**
  - `tests/test_dump_finder.py`: kiểm tra `find_dumps` chấp nhận `Path`, `str`, danh sách `Path`/`str`, file đơn lẻ và đường dẫn không tồn tại.
  - `tests/test_pipeline.py`: kiểm thử đầu-cuối nguồn `folder`, nguồn `local` giả lập, trường hợp 0 dump, huỷ phân tích và đối chiếu tương đồng 100% giữa kết luận GUI và CLI.
  - `tests/test_gui_worker.py`: kiểm thử worker chạy đồng bộ, worker phát tín hiệu lỗi kèm chi tiết, worker huỷ tiến trình an toàn.
  - `tests/test_gui.py`: bổ sung smoke test toàn diện nạp payload pipeline, chuyển qua lại 6 tab, xuất báo cáo HTML và Excel không văng lỗi.
- **Ghi nhận Quyền Tác Giả & Tối ưu hoá Bố cục Giao diện Người dùng:**
  - **Quyền tác giả phát triển phần mềm:** Ghi nhận chính thức tác giả **Lilbow** trên `pyproject.toml`, `__init__.py`, giao diện dòng lệnh `cli.py` (`dumpanalyzer --version`), tiêu đề chính ứng dụng và Thẻ Thông tin phần mềm & Bản quyền.
  - **Cân đối lại Tab Cài đặt (`src/dumpanalyzer/gui/tab_settings.py`):** Bọc toàn bộ giao diện trong `QScrollArea` cuộn mượt mà; cấu trúc lại bảng cấu hình với cột nhãn tối thiểu 240px, tách bạch các trường nhập liệu và spinbox trên từng hàng độc lập kèm giải thích trực quan, giải quyết triệt để tình trạng nhãn và ô chọn bị dồn ép sát nhau.
  - **Tái cấu trúc Tab Kết luận (`src/dumpanalyzer/gui/tab_verdict.py`):** Phân chia mục Đánh giá độ chính xác kết luận (Feedback) thành 3 hàng thoáng mát: hàng 1 chọn kết luận và nguyên nhân thực tế, hàng 2 nhập ghi chú kinh nghiệm rộng rãi chiếm trọn chiều ngang, hàng 3 nút Lưu phản hồi và trạng thái thông báo.
  - **Tối ưu Thanh công cụ Toolbar (`src/dumpanalyzer/gui/main_window.py`):** Khi chọn "Máy cục bộ này", tự động ẩn ô nhập đường dẫn thư mục và hiển thị thông điệp quét tự động thư mục hệ thống mặc định; chỉ hiển thị ô nhập và nút "📁 Duyệt thư mục..." khi người dùng chọn nguồn "Thư mục dump đã thu về".

---

## [v1.2.0] - 2026-11-03

### Đợt Cập nhật 04 — Củng cố Sẵn sàng Ghi Dump & Quản lý Cấu hình Toàn đội
- **Phần A — Củng cố Bộ kiểm tra Sẵn sàng ghi dump (`collectors/dump_config.py`):**
  - Trả về có cấu trúc, tách bạch hoàn toàn lỗi đọc Registry (`read_ok=False`) và giá trị chưa cấu hình (`value_present=False`, sửa L1).
  - Tách 3 trạng thái bộ nhớ ảo (Pagefile): `ok` (đủ), `missing` (thiếu hoàn toàn), `unknown` (lỗi đọc WMI/Registry), đồng thời công nhận `DedicatedDumpFile` độc lập (sửa L3, L6).
  - Kiểm tra dung lượng đĩa hệ thống và RAM theo ngưỡng cấu hình động tương ứng từng chế độ mục tiêu 7/3 (sửa L5).
  - Sắp xếp và đánh giá sự kiện `volmgr` (161/162/45/46/49) theo đúng thứ tự thời gian UTC; sự kiện ghi dump thành công (162) sau sự cố sẽ xóa cảnh báo lỗi (sửa L4).
  - Theo dõi thời điểm khởi động máy gần nhất (`get_last_boot_time_utc`), gắn cờ `pending_reboot` và trạng thái `READY_PENDING_REBOOT` khi cấu hình mới chưa qua khởi động lại (sửa L7).
  - Đánh giá khả năng sẵn sàng qua `evaluate_readiness_v2` với 5 trạng thái chuẩn (`READY`, `READY_PENDING_REBOOT`, `ATTENTION`, `BLOCKED`, `UNKNOWN`) và 3 mức chứng minh (`evidence_of_success`, `configured_only`, `none`).
- **Phần B — Bật ghi dump Cục bộ An toàn & Hoàn tác 100%:**
  - Quy tắc an toàn tối thượng P1-P11: Tuyệt đối KHÔNG tự ý khởi động lại máy tính (không gọi `shutdown`, `Restart-Computer`).
  - Cơ chế sao lưu kép L2 (`backup_registry_crash_control_v2`): Lưu đồng thời file JSON (nguồn sự thật) và file `.reg` an toàn (sử dụng cú pháp `"CrashDumpEnabled"=-` cho giá trị vốn không tồn tại).
  - Xác nhận bắt buộc: Yêu cầu xác nhận rõ ràng trước khi ghi (`confirmed=True` hoặc cờ `--yes`).
  - Kiểm tra đọc lại sau ghi (Read-after-write): Nếu giá trị đọc lại không khớp, tự động kích hoạt hoàn tác tự động ngay lập tức và cảnh báo cho người dùng.
  - Hoàn tác 100% (`rollback_crash_dump`): Phục hồi chính xác trạng thái ban đầu, tự động gọi `DeleteValue` nếu ban đầu giá trị chưa từng tồn tại.
  - Ghi nhật ký kiểm toán (Audit Log): Tự động lưu vết mọi thay đổi vào file `logs/dump_config_changes.jsonl` và bảng SQLite `dump_config_change`.
- **Phần C — Giao diện GUI & Công cụ dòng lệnh CLI:**
  - Tab GUI số 6 "Sẵn sàng ghi dump" (`src/dumpanalyzer/gui/tab_dump_readiness.py`):
    - Khu vực 1 (Máy cục bộ): Huy hiệu trạng thái lớn, mức chứng minh, 4 thẻ chi tiết (Registry, Pagefile, Ổ đĩa/RAM, volmgr), danh sách lý do và khuyến nghị, các nút chức năng an toàn ([Kiểm tra lại], [Bật ghi dump], [Hoàn tác...], [Xuất gói triển khai], [Mở thư mục sao lưu]).
    - Khu vực 2 (Toàn đội máy): Nút chọn thư mục chia sẻ mạng, 4 thẻ KPI tổng quan, bảng danh sách máy có bộ lọc trạng thái và ô tìm kiếm, nút [Xuất Excel báo cáo đội máy].
    - Tab Kết luận: Bổ sung thanh cảnh báo màu nổi bật khi máy chưa ở trạng thái `READY`, kèm nút liên kết chuyển nhanh sang Tab Sẵn sàng ghi dump.
  - Bổ sung 6 lệnh CLI mới trong `src/dumpanalyzer/cli.py`:
    - `dumpanalyzer dump-readiness`: Kiểm tra và in báo cáo định dạng bảng hoặc JSON (`--json`), xuất file JSON (`--out`).
    - `dumpanalyzer dump-enable`: Bật ghi dump tự động (mặc định 7) hoặc minidump (3) kèm sao lưu kép, mã thoát 2 khi cấu hình đã có sẵn (idempotent).
    - `dumpanalyzer dump-rollback`: Hoàn tác từ bản sao lưu JSON, yêu cầu xác nhận hoặc `--yes`.
    - `dumpanalyzer dump-package`: Xuất gói triển khai gồm `Enable-CrashDump.ps1`, `Rollback-CrashDump.ps1`, và `README_TRIEN_KHAI.txt`.
    - `dumpanalyzer dump-fleet`: Tổng hợp các báo cáo JSON từ thư mục chia sẻ mạng, tính toán KPI và xuất Excel 3 sheet.
    - `dumpanalyzer selftest`: Tự kiểm tra CSDL, quy tắc chẩn đoán và module sẵn sàng ghi dump.
- **Phần D — Triển khai Toàn đội & Báo cáo Tổng hợp (`engine/deployment_package.py`):**
  - Gói triển khai PowerShell an toàn:
    - `Enable-CrashDump.ps1`: Tuân thủ ma trận 3.3, hỗ trợ tham số `[switch]$WhatIf`, sao lưu kép vào `%ProgramData%\DumpAnalyzer\backup`, xuất báo cáo JSON về thư mục chia sẻ mạng nếu có `-ReportDir`, không chứa lệnh khởi động lại.
    - `Rollback-CrashDump.ps1`: Tự động tìm bản sao lưu JSON gần nhất hoặc theo đường dẫn chỉ định để hoàn tác sạch.
  - Bộ tổng hợp đội máy (`aggregate_fleet_reports`): Xử lý bền vững các file JSON bị lỗi/hỏng cấu trúc, tự động phát hiện báo cáo cũ/lỗi thời (> 14 ngày).
  - Báo cáo Excel 3 sheet (`export_fleet_readiness_excel`): Sheet 1 "Tổng quan KPI & Lý do", Sheet 2 "Danh sách máy trạm & Trạng thái", Sheet 3 "Máy cần can thiệp gấp".
- **Phần E — Phân tích Không có Dump (`log_only`) & Bù đắp Dump Gap:**
  - Chuẩn hoá mã lỗi BugcheckCode của Kernel-Power Event 41: Chuyển đổi chính xác từ decimal sang hex chuẩn (`f"0x{val:X}"`, lưu `bugcheck_hex_8` trong `extra_json`), phân loại mã 0 thành `non_bsod_reset` ("Tắt máy/Mất nguồn đột ngột, không có BSOD").
  - Tính toán độ hẫng dump (`compute_dump_gap`, sửa L9): Đối chiếu số lần sập BSOD thực tế từ Event Log với số file dump thu thập được, loại trừ các lần sập trước thời điểm bật cấu hình, cảnh báo khi phát hiện dump bị thất thoát.
- **Phần F — Cơ sở dữ liệu & Cấu hình:**
  - Bổ sung bảng `dump_readiness` và `dump_config_change` vào `schema.sql` và CSDL SQLite.
  - Quy tắc chẩn đoán mới `config/rules/dump_readiness.yaml` và cấu hình mặc định `dump_readiness` trong `settings.yaml`.
  - Bộ kiểm thử tự động toàn diện `tests/test_dump_readiness.py` bao phủ 15 kịch bản theo yêu cầu tài liệu, chạy pass 100% trên Linux và Windows.

---

## [v1.1.1] - 2026-11-03

### Bản vá HOTFIX 01 — Sửa lỗi đóng gói thiếu schema.sql
- **Cấu hình đóng gói PyInstaller (`DumpAnalyzer.spec`):**
  - Khai báo biến `SCHEMA_SQL` trỏ tới `src/dumpanalyzer/storage/schema.sql`.
  - Bổ sung `datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')]` cho cả hai cấu hình `Analysis` (GUI `a_gui` và CLI `a_cli`).
  - Đảm bảo file được đóng gói vào `_internal/dumpanalyzer/storage/schema.sql`.
  - Bổ sung các hiddenimports cần thiết (`dumpanalyzer.storage.db`, `dumpanalyzer.hwtests`, `dumpanalyzer.gui.tab_hwtests`, `dumpanalyzer.engine.fleet`, `dumpanalyzer.collectors.sysinfo`, `dumpanalyzer.collectors.asset_info`).
- **Cơ chế tìm kiếm schema bền vững (`src/dumpanalyzer/storage/db.py`):**
  - Triển khai hàm `_find_schema_file() -> Path` thử lần lượt:
    1. `sys._MEIPASS / dumpanalyzer / storage / schema.sql` (bản build đóng gói PyInstaller 6.x).
    2. `sys._MEIPASS / storage / schema.sql` (phương án dự phòng đóng gói trực tiếp).
    3. `__file__.parent / schema.sql` (môi trường phát triển từ mã nguồn).
  - Báo lỗi chi tiết bằng tiếng Việt liệt kê toàn bộ các đường dẫn đã thử kèm gợi ý khắc phục khi không tìm thấy.
- **Khai báo package data (`pyproject.toml`):**
  - Bổ sung cấu hình `[tool.setuptools.package-data]` cho `dumpanalyzer = ["storage/schema.sql"]` hỗ trợ cài đặt bằng `pip install`.
- **Tự động hóa CI/CD GitHub Actions (`.github/workflows/build.yml`):**
  - Bổ sung bước kiểm tra sự hiện diện của `schema.sql` trong thư mục `dist/DumpAnalyzer` bằng PowerShell `Get-ChildItem`.
  - Bổ sung bước chạy thử nghiệm lệnh CLI khởi tạo CSDL `DumpAnalyzer-cli.exe feedback stats` để xác thực gói build thực tế.
  - Chuẩn hoá lệnh gọi `python -m pytest -v` theo quy tắc `python-windows-ci-guard`.
- **Bộ kiểm thử tự động (`tests/test_packaging.py`):**
  - Bổ sung 7 test case kiểm thử toàn diện: chạy từ mã nguồn, giả lập `sys._MEIPASS`, giả lập lỗi thiếu file, kiểm tra khai báo trong `DumpAnalyzer.spec`, kiểm tra `pyproject.toml`, và kiểm tra khởi tạo CSDL thực tế. Chạy xanh 100% trên Linux.

---

## [v1.1.0] - 2026-11-03

### Đợt Cập nhật 03 — Nâng Độ Chính Xác Kết Luận + Khung Test Phần Cứng
- **Phần 0 — Sửa lỗi CI GitHub Actions:**
  - Bổ sung `ruff>=0.5.0` vào nhóm `dev` trong `pyproject.toml` và cấu hình `tool.ruff`.
  - Sửa `.github/workflows/build.yml` gọi lint qua `python -m ruff check src` độc lập PATH.
- **Phần 1 — Thu thập thêm Dữ liệu Tăng Bằng chứng:**
  - Mở rộng WinDbg CDB runner/parser: trích xuất `FAILURE_BUCKET_ID`, phân tích lỗi vi kiến trúc `!errrec` cho Bug Check 0x124, kiểm tra tính toàn vẹn nhân `!chkimg -d nt`, tính tuổi driver bằng `lmvm`. Thêm cờ `--save-cdb-samples` lưu mẫu thô vào `workspace/cdb_samples/`.
  - Mở rộng Event Log collector: tích hợp Kernel-PnP 219, Code Integrity 3033/3063, Application Error 1000 đa ứng dụng, Display 4101 TDR, Kernel-Processor-Power 37, và EventData mở rộng cho Kernel-Power 41.
  - Collector mới `sysinfo.py`: thu thập thông số phần cứng chỉ đọc (RAM speed/overclock, đĩa SMART/HealthStatus/PowerOnHours, BIOS age, GPU driver age), lưu bảng `system_info`.
  - Collector mới `asset_info.py`: nhập danh mục thiết bị từ file CSV xuất từ Google Sheets / AppSheet qua CLI `dumpanalyzer asset import` và giao diện, lưu bảng `asset_info`.
- **Phần 2 — Vòng Phản hồi, Lịch sử Máy & Đội máy:**
  - Cơ sở dữ liệu và CLI Feedback: thêm bảng `feedback`, lệnh CLI `dumpanalyzer feedback add|list|stats`. Thống kê tỷ lệ chính xác chỉ hiển thị khi có >= 10 ca đánh giá.
  - Lịch sử theo máy: tích hợp `history_lookback_days` (mặc định 180 ngày) truy vấn toàn bộ lịch sử crash đã lưu trong SQLite của máy trước khi chấm điểm. Tab Chi tiết hiển thị bảng Crash Timeline.
  - Phân tích Đội máy (`fleet.py`): gom crash theo `FAILURE_BUCKET_ID` và `suspect_driver` trên >= N máy trong D ngày, sinh bằng chứng medium cho driver/phần mềm diện rộng.
- **Phần 3 — Tách Độ tin cậy khỏi Điểm nghi ngờ & Gợi ý bước tiếp theo:**
  - Mô hình bằng chứng nâng cao: thêm `strength` (`strong|medium|weak`), `group_id` độc lập, `polarity` (`support|refute`). Bằng chứng phản bác làm giảm điểm nhóm tương ứng (sàn 0.0).
  - Tách bạch 2 chỉ số: `suspicion_share` (0–100%) và `confidence` (`cao`, `trung bình`, `thấp`) theo chính sách `confidence_policy`. Mã Bug Check đơn lẻ chỉ đạt độ tin cậy thấp.
  - Bộ gợi ý `next_steps.yaml`: sinh khuyến nghị theo từng nhóm nghi ngờ và tự động nhận diện dữ liệu còn thiếu.
- **Phần 4 — Khung Plugin Kiểm tra Phần cứng (`hwtests`):**
  - Khung plugin `HardwareTest`, `TestResult`, quy đổi kết quả sang Evidence qua `test_rules.yaml`.
  - Plugin `storage_health`: chạy `chkdsk /scan` chỉ đọc an toàn, chặn tuyệt đối các cờ phá hủy `/f`, `/r`, `/spotfix`.
  - Plugin `windows_memory_diagnostic`: gọi `mdsched.exe` hẹn giờ test RAM, thu thập kết quả Event Log sau reboot, ID lạ chưa biết gán `inconclusive`.
  - Plugin `external_test_import`: nhập kết quả từ MemTest86, OCCT, Prime95; quy tắc >= 4 passes 0 lỗi là `passed`.
  - Xuất phiếu hướng dẫn kiểm tra RAM chuẩn mực bằng USB boot MemTest86 tiếng Việt.
  - Tab mới "Kiểm tra phần cứng" trên PySide6 GUI với quản lý lịch sử kiểm tra.
- **Phần 5 — Báo cáo & Tài liệu:**
  - Xuất Excel tích hợp thêm Sheet "Thống kê phản hồi" và Sheet "Tổng quan đội máy", bổ sung cột Độ mạnh và Chiều hướng trong Sheet Bằng chứng.
  - Cập nhật `RULES_GUIDE.md` và `README.md`.

---

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

### Sửa lỗi CI (Đợt Cập nhật 03)
- **Cấu hình phụ thuộc dev (`pyproject.toml`):**
  - Thêm `ruff>=0.5.0` vào nhóm `dev` trong `pyproject.toml` để runner CI tự động cài đặt công cụ lint.
  - Thiết lập cấu hình `[tool.ruff]` và `[tool.ruff.lint]` (`select = ["F"]`, `line-length = 120`, `target-version = "py311"`) đảm bảo kết quả lint đồng nhất tuyệt đối giữa môi trường dev và CI.
- **Quy trình GitHub Actions (`.github/workflows/build.yml`):**
  - Gọi công cụ lint qua `python -m ruff check src` thay vì `ruff` trực tiếp để loại bỏ hoàn toàn lỗi `"The term 'ruff' is not recognized"` trên runner Windows PowerShell.
  - Duy trì biến môi trường `PYTHONIOENCODING: "utf-8"` và `PYTHONUTF8: "1"` để xử lý triệt để bảng mã cp1252.

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
