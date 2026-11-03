# ĐỢT CẬP NHẬT 02 — SỬA LỖI DumpAnalyzer (v1.0.0 → v1.0.1)

> Dán toàn bộ nội dung từ mục "PROMPT" bên dưới vào Antigravity. Repo: `DumpAnalyzer/` (đang ở tag v1.0.0, 85 test đang PASS).

---

## PROMPT

Bạn là kỹ sư phần mềm đang tiếp quản dự án **DumpAnalyzer** (Python, PySide6, SQLite, YAML rules). Nhiệm vụ của đợt này là **SỬA LỖI**, không thêm tính năng mới. Các lỗi dưới đây đã được xác minh bằng cách chạy code (nhóm A) hoặc phát hiện qua đọc code (nhóm B–F). Người dùng KHÔNG biết lập trình, nên mọi thay đổi phải có test và báo cáo rõ ràng bằng tiếng Việt.

### 0. NGUYÊN TẮC BẮT BUỘC

1. Trước khi sửa: `git status` sạch, tạo nhánh `fix/update-02` từ `main`.
2. Mỗi nhóm lỗi = 1 commit riêng, message dạng `fix(scorer): ...`. Không gộp.
3. Với MỖI lỗi: **viết test tái hiện lỗi trước (phải FAIL trên code cũ), rồi mới sửa cho test PASS.** Ghi lại trong báo cáo rằng test đã fail trước khi sửa.
4. Không đổi tên module/hàm công khai, không đổi định dạng file YAML theo cách làm hỏng file cũ của người dùng. Nếu cần thêm khóa YAML thì phải tương thích ngược (khóa thiếu → dùng mặc định).
5. Không phân tích/ghi lên file dump gốc. Không tự ý chạy lệnh sửa registry.
6. **Không bịa.** Những thứ không thể kiểm chứng trên môi trường hiện tại (Windows thật, dump thật, PowerShell thật) phải ghi rõ trong báo cáo là "CHƯA KIỂM CHỨNG — cần người dùng test trên Windows" kèm đúng lệnh để họ chạy. Nếu một giả định (ví dụ offset trong header) không xác minh được từ tài liệu công khai, hãy nói rõ và KHÔNG sửa bừa.
7. Sau mỗi nhóm: chạy `python -m pytest tests -q` (toàn bộ phải PASS). Cuối cùng cập nhật `CHANGELOG.md` (mục `[v1.0.1]`) và `docs/RULES_GUIDE.md` nếu ngữ nghĩa luật thay đổi, rồi gắn tag `v1.0.1`.

---

### NHÓM A — Lỗi lõi chấm điểm (ƯU TIÊN CAO NHẤT)

**A1. Sự kiện WHEA không bao giờ được chấm điểm**
- Vị trí: `src/dumpanalyzer/engine/correlator.py`, hàm `correlate_events_to_crash` (đoạn gán `kind`); `src/dumpanalyzer/engine/scorer.py` (`score_single_crash` và vòng lặp tính `log_pts_crash` trong `score_machine_crashes`).
- Hiện tượng: provider chứa "WHEA" bị gán `kind = "hardware"`, nhưng scorer chỉ xử lý `kind` ∈ {`eventlog`, `smart`, `update`}. Kết quả: BSOD 0x124 kèm WHEA ID 18 cho điểm GIỐNG HỆT lúc không có sự kiện (cpu 40 / ram 30 / psu 20).
- Cách sửa:
  - Mọi sự kiện lấy từ Windows Event Log phải có `kind = "eventlog"` và được khớp với `event_rules.yaml` theo `source` + `ids`. Bỏ nhánh `"hardware"`.
  - Nhánh `kind = "smart"` chỉ dành cho dữ liệu SMART thật (từ `collect_smart_status`), không suy ra từ tên provider. Xóa đoạn `"smart" if "smart" in prov.lower()` vô nghĩa.
  - `kind = "update"` chỉ dành cho bằng chứng KB/phần mềm từ `correlate_recent_updates`. Sự kiện provider `WindowsUpdateClient` / `MsiInstaller` phải đi qua `event_rules.yaml` như sự kiện thường (tránh cộng điểm kép và tránh cộng cứng +25).
  - Tách logic "tính điểm từ danh sách bằng chứng" thành MỘT hàm dùng chung (ví dụ `compute_event_points(evidences, rules, initial_top_suspects)`), để `score_single_crash` và `score_machine_crashes` (phần `log_hypotheses`) không còn đoạn code trùng lặp.
- Test hồi quy: `tests/test_scorer.py` — crash 0x124 + 1 evidence WHEA ID 18 → điểm `cpu` PHẢI cao hơn trường hợp không có evidence. Thêm test đi qua `Correlator.correlate_events_to_crash` từ dict sự kiện thô (không dựng Evidence bằng tay) rồi mới chấm điểm, để test bắt được lỗi kiểu này.

**A2. Giá trị `cap` trong `event_rules.yaml` bị bỏ qua**
- Hiện tượng: 1 sự kiện Disk ID 7 → storage ~48%; 20 sự kiện → ~83%. Một ổ đĩa spam log lấn át mọi bằng chứng khác dù YAML đã khai báo `cap`.
- Ngữ nghĩa cần hiện thực: với mỗi **(luật, nhóm nghi ngờ)**, tổng điểm cộng từ tất cả sự kiện khớp luật đó trong MỘT crash không được vượt `cap` của luật. Áp dụng `cap` SAU khi nhân hệ số đồng thuận 1.5. Luật không có `cap` → không giới hạn (tương thích ngược).
- Áp dụng cùng ngữ nghĩa ở mức máy (dùng chung hàm A1).
- `rule_loader.validate_event_rules`: kiểm tra `cap` là số > 0 và cảnh báo nếu `cap` nhỏ hơn trọng số 1 lần cộng của luật.
- Ghi ngữ nghĩa `cap` vào `docs/RULES_GUIDE.md`.
- Test: 2 sự kiện Disk ID 7 và 20 sự kiện Disk ID 7 phải cho CÙNG điểm storage; 1 sự kiện phải thấp hơn hoặc bằng.

**A3. Thiếu `import json` trong `correlator.py`**
- Hiện tượng: `json.dumps(...)` được gọi khi sự kiện có `event_data` mà `raw_message` rỗng → `NameError`.
- Sửa: thêm `import json`. Sau đó chạy `ruff check src --select F` (hoặc `pyflakes src`) và sửa TOÀN BỘ lỗi tên chưa định nghĩa / import thừa trong dự án. Thêm bước này vào `.github/workflows/build.yml` (chạy trước pytest).
- Test: sự kiện `provider="Disk", event_id=7, raw_message="", event_data={"a": 1}` → không ném lỗi, `detail` chứa JSON.

**A4. Các pattern trong `patterns.yaml` kích hoạt sai/không dùng đúng tham số**
- Vị trí: `score_machine_crashes`, đoạn "Áp dụng patterns.yaml".
- Lỗi cụ thể:
  1. Pattern "Module lỗi thay đổi liên tục, toàn module Microsoft": biến `all_microsoft_modules` mặc định True. Với dump `header_only` (không có `image_name`) pattern vẫn kích hoạt chỉ vì ≥3 mã bug check khác nhau. → Chỉ tính các crash có `image_name` (đã qua cdb); yêu cầu số crash đó ≥ `min_dumps`; đếm số **module** khác nhau (`image_name`), không đếm mã bug check, so với `distinct_modules_min`.
  2. Pattern "sau cập nhật": giá trị `first_crash_within_days_after_update: 7` bị bỏ qua (chỉ kiểm tra có evidence update hay không). → Chỉ kích hoạt nếu có bản cập nhật trong N ngày (N lấy từ chính pattern) trước crash đầu tiên.
  3. Pattern "mất nguồn": điều kiện `no_dump: true` bị bỏ qua. → Chỉ kích hoạt khi crash có KP41 BugcheckCode=0 là crash `log_only`.
  4. `driver_of_module` đang bị gộp vào nhóm chung `"driver"`. → Cộng điểm vào đúng nhóm theo `driver_map.yaml` (ví dụ `gpu`) nếu module có trong map, nếu không thì `driver:<tên module>`.
- Test: 3 crash `header_only` mã khác nhau → pattern 1 KHÔNG kích hoạt; 3 crash cdb với 3 module Microsoft khác nhau → kích hoạt; cập nhật cách crash 10 ngày với N=7 → không kích hoạt.

---

### NHÓM B — Đọc header dump (CẦN XÁC MINH TRƯỚC KHI SỬA)

- Vị trí: `src/dumpanalyzer/analyzer/header_parser.py`, nhánh `PAGEDU64`.
- Nghi vấn: code đọc `SystemTime` tại offset `0xA0`. Theo cấu trúc `_DUMP_HEADER64` công khai, `SystemTime` nằm gần `0xFA8`, `DumpType` gần `0xF98`, `SystemUpTime` gần `0xFF8`. Hiện tại giá trị luôn rơi về `mtime` của file mà không báo.
- Việc cần làm:
  1. Đối chiếu offset với tài liệu công khai đáng tin cậy (Windows SDK/WDK `ntdddump.h`, ReactOS, hoặc cấu trúc của Volatility/rekall). **Ghi rõ nguồn đã dùng trong báo cáo.** Nếu không xác minh được, DỪNG và báo lại, không đoán.
  2. Nếu xác minh đúng: sửa offset `SystemTime`; đọc thêm `DumpType` (1=full, 2=kernel/summary, 3=header, 4=triage/mini) để điền `dump_type` thay vì luôn là `"kernel"`; đọc `SystemUpTime` (đơn vị 100 ns) nếu hợp lý.
  3. Thêm trường `crash_time_source` (`"header"` hoặc `"mtime"`) vào `DumpHeaderInfo` và cột tương ứng vào bảng `crash` (migration tương thích ngược trong `db.py`), hiển thị nguồn thời gian trong Tab "Chi tiết crash" và báo cáo (để người dùng biết giờ sập là chính xác hay chỉ là giờ sửa file).
  4. Cập nhật `tests/fixtures/generate_cdb_fixtures.py` / fixture `.dmp` theo đúng offset mới. Lưu ý: fixture hiện do chính dự án tự sinh theo giả định cũ nên test cũ luôn tự nhất quán; ghi chú trong báo cáo rằng fixture là **dữ liệu tổng hợp**, cần so sánh thêm với dump thật.
- **CHƯA KIỂM CHỨNG trên dump thật** → liệt kê lệnh để người dùng chạy: `dumpanalyzer scan` trên máy có dump thật, rồi so giờ crash/mã lỗi với `BlueScreenView` hoặc `cdb !analyze -v`.

---

### NHÓM C — Đọc Event Log bằng PowerShell

- Vị trí: `src/dumpanalyzer/collectors/eventlog.py`, hàm `read_system_events` (và truy vấn tương tự trong `dump_config.check_volmgr_events` nếu có cùng kiểu lỗi).
- Nghi vấn lỗi cú pháp: script có dạng `foreach ($e in $events) { ... } | ConvertTo-Json`. Trong PowerShell, không thể đưa câu lệnh `foreach` vào pipe (thường báo "An empty pipe element is not allowed"). Nếu đúng thì hàm trả về `[]` và chỉ ghi log mức DEBUG → công cụ chạy "thành công" nhưng không có sự kiện nào.
- Việc cần làm:
  1. Viết lại script: lọc ngay trong `Get-WinEvent -FilterHashtable` (dùng `ProviderName=@(...)`, `Id=@(...)`, `StartTime`, `EndTime`) thay cho `Where-Object` trên toàn bộ log; dùng `ForEach-Object` (không dùng câu lệnh `foreach`) rồi `ConvertTo-Json -Depth 4 -Compress`; đặt `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`.
  2. Phân biệt rõ 3 trạng thái: (a) không có sự kiện nào khớp (hợp lệ), (b) PowerShell lỗi (returncode ≠ 0 hoặc stderr có nội dung), (c) timeout. Trường hợp (b),(c) phải ghi log mức WARNING kèm stderr và trả về cảnh báo cho GUI/CLI hiển thị ("Không đọc được Event Log: ..."), KHÔNG được im lặng.
  3. Timeout lấy từ `settings.yaml` (khóa mới `eventlog_timeout_seconds`, mặc định 120).
  4. Thêm tuỳ chọn `dumpanalyzer events --debug-ps` in ra đúng script PowerShell đã chạy, returncode, stderr và 500 ký tự đầu của output để người dùng gửi lại khi gặp sự cố.
  5. Tách phần dựng script thành hàm riêng (`build_eventlog_script(...)`) để test được.
- Test (chạy được trên Linux): kiểm tra chuỗi script do `build_eventlog_script` sinh ra có chứa `-FilterHashtable`, có `ForEach-Object`, KHÔNG có mẫu `foreach (` theo sau bởi `} |`; test xử lý các trạng thái (a)(b)(c) bằng `subprocess.run` được mock.
- **CHƯA KIỂM CHỨNG trên Windows thật** → người dùng chạy:

```cmd
dumpanalyzer events --debug-ps
```

---

### NHÓM D — Giờ sập của crash `log_only`

- Vị trí: `correlator.detect_log_only_crashes`, `correlate_events_to_crash`.
- Vấn đề: Event 41 (Kernel-Power) được ghi **khi máy khởi động lại**, không phải lúc sập. Dùng giờ Event 41 làm `crash_time_utc` khiến cửa sổ 10 phút trước crash bị lệch, có thể bỏ sót sự kiện nguyên nhân (WHEA, Disk...).
- Cách làm (theo thứ tự ưu tiên, lùi dần):
  1. Nếu có Event 6008 ("lần tắt máy trước bất thường") và parse được thời điểm tắt máy từ `EventData` → dùng.
  2. Nếu không: ước lượng bằng sự kiện cuối cùng trong System log TRƯỚC thời điểm khởi động (thu thêm Event 6005 / Kernel-General ID 12 để xác định mốc khởi động).
  3. Nếu không được: dùng giờ Event 41 như hiện tại.
- Gắn `crash_time_source` = `"eventlog_6008"`, `"estimated"` hoặc `"kp41"` (dùng chung cột ở Nhóm B). Cửa sổ tương quan cho crash `log_only` là `[crash_time − window, giờ Event 41]`.
- Nếu việc parse 6008 quá phức tạp do định dạng ngày giờ theo ngôn ngữ, hãy làm bước 2 + 3 và báo cáo rõ phần chưa làm. Không bịa định dạng ngày giờ.
- Test: dữ liệu mock có WHEA lúc 03:00, sự kiện cuối cùng 03:01, Event 6005 lúc 03:12, Event 41 lúc 03:12 → WHEA PHẢI nằm trong bằng chứng của crash.

---

### NHÓM E — Event 1001 không phụ thuộc ngôn ngữ

- Vị trí: `eventlog.parse_bugcheck_1001_message`, `read_system_events`.
- Vấn đề: đang dùng regex tiếng Anh ("bugcheck was:", "dump was saved in:") trên `Message` → hỏng trên Windows ngôn ngữ khác. Filter `Id 1001` cũng không giới hạn provider (trùng với WER 1001 của log Application).
- Sửa: lọc `ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'` (và nhận cả `BugCheck` nếu có); đọc từ `EventData` trong XML (trường `param1` dạng `0x000000xx (p1, p2, p3, p4)` và `param2` là đường dẫn dump). Giữ regex trên message làm phương án dự phòng.
- Test: sự kiện có `raw_message` rỗng và `event_data = {"param1": "0x0000009f (0x3, 0xffffe0, 0xffffd0, 0xffffc0)", "param2": "C:\\Windows\\MEMORY.DMP"}` → bugcheck `0x9F`, đủ 4 tham số, đúng đường dẫn dump.

---

### NHÓM F — Dọn dẹp thiết kế nhỏ (làm nếu còn thời gian, mỗi mục 1 commit)

1. **Tên driver nghi vấn:** hiện scorer tìm chuỗi `"Driver nghi vấn trong stack:"` trong `cdb_raw_output`. → Thêm cột `suspect_driver` vào bảng `crash` (migration tương thích ngược), lưu từ `CdbAnalysisResult.suspect_driver`; scorer ưu tiên cột này, chỉ dùng chuỗi cũ khi cột rỗng (dữ liệu DB cũ).
2. **File lớn (MEMORY.DMP nhiều GB):** trước khi copy vào workspace, kiểm tra dung lượng trống (cần ≥ kích thước file × 1.2). Nếu không đủ hoặc file lớn hơn `max_copy_gb` (khóa mới trong `settings.yaml`, mặc định 8) → không copy; chỉ đọc header + chạy cdb trực tiếp ở chế độ chỉ đọc và hiện cảnh báo rõ. Với file rất lớn, khóa cache dùng "băm nhanh" (kích thước + mtime + SHA256 của 1 MB đầu và 1 MB cuối) và ghi rõ đó là băm nhanh.
3. **Dữ liệu thật trong gói phát hành:** đảm bảo `data/*.db`, `workspace/`, `logs/` nằm trong `.gitignore` và KHÔNG được đưa vào `DumpAnalyzer.spec` / zip phát hành.

---

### KHÔNG LÀM TRONG ĐỢT NÀY (để đợt sau, đừng tự ý mở rộng)

- Đổi cách tính "độ tin cậy" (tách điểm nghi ngờ khỏi độ tin cậy).
- Mở rộng `driver_map.yaml` / `bugcheck_rules.yaml`.
- Thay đổi giao diện GUI ngoài việc hiển thị `crash_time_source` và cảnh báo lỗi đọc Event Log.

---

### ĐỊNH DẠNG BÁO CÁO CUỐI (bắt buộc, bằng tiếng Việt)

Với mỗi nhóm A–F, báo cáo:
1. **Đã sửa gì** (tên file + hàm).
2. **Test đã thêm** (tên test) và xác nhận **đã FAIL trước khi sửa / PASS sau khi sửa**.
3. **Điểm CHƯA KIỂM CHỨNG** cần người dùng test trên Windows, kèm đúng lệnh để chạy.
4. **Việc bỏ dở / quyết định đã đưa ra** và lý do.

Cuối báo cáo: kết quả `pytest` (số test PASS/tổng), kết quả `ruff check src --select F`, danh sách commit và tag `v1.0.1`.

---

## PHỤ LỤC — Việc người dùng tự kiểm tra trên Windows sau khi Antigravity xong

1. `dumpanalyzer events --debug-ps` trên một máy thật: có ra sự kiện không? Có dòng lỗi PowerShell nào không?
2. `dumpanalyzer scan` trên máy có file dump thật: so **giờ crash** và **mã Bug Check** với BlueScreenView.
3. Tạo một BSOD thử bằng NotMyFault (xem `docs/TESTING_WITH_NOTMYFAULT.md`) rồi chạy GUI: kiểm tra Tab "Chi tiết crash" có hiện đúng nguồn giờ sập và bảng sự kiện.
