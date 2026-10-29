# BÀN GIAO ANTIGRAVITY — Công cụ phân tích Dump (BSOD) + Event Log

> Tài liệu này là **nguồn sự thật duy nhất** (single source of truth) cho dự án.
> Antigravity phải đọc toàn bộ trước khi viết dòng code đầu tiên, và làm **tuần tự từng Phase**.

---

## 0. TÓM TẮT NHANH

| Mục | Nội dung |
|---|---|
| Tên dự án | `DumpAnalyzer` (có thể đổi) |
| Mục tiêu | Đọc và phân tích file dump (BSOD) kết hợp Event Log để **khoanh vùng nguyên nhân** gây màn hình xanh / tự khởi động lại, rồi đưa ra kết luận có điểm tin cậy và bằng chứng |
| Người dùng | Nhân viên IT quản lý máy tính, máy in trong công ty. **Không có nền tảng lập trình** |
| Nền tảng | Windows 10/11, chạy cục bộ trên máy IT (và có thể phân tích dump copy từ máy khác về) |
| Ngôn ngữ giao diện | Tiếng Việt |
| Ngôn ngữ code/comment | Tên biến, hàm bằng tiếng Anh; **comment và docstring bằng tiếng Việt** |

### Tài sản đã có (người dùng sẽ cung cấp, hãy kiểm tra trong repo trước khi hỏi)

1. Công cụ Event Log hiện tại (PowerShell + `.bat`, đã có bản giao diện) — đọc Event Log theo khoảng thời gian, tra mã Bug Check ra nhóm nguyên nhân. **Hãy đọc mã nguồn này trước, tái sử dụng logic và danh sách hợp lý, không viết lại mù quáng.**
2. Danh sách đầy đủ **~380 mã Bug Check** của Microsoft (dùng để nhúng làm dữ liệu tra cứu).

Nếu không tìm thấy hai tài sản trên trong repo, **dừng lại và hỏi người dùng** thay vì tự bịa dữ liệu.

---

## 1. NGUYÊN TẮC BẮT BUỘC (đọc kỹ)

1. **Làm từng Phase, dừng ở tiêu chí nghiệm thu.** Không tự nhảy sang Phase sau. Cuối mỗi Phase: tóm tắt đã làm gì, cách chạy thử, kết quả test, và chờ người dùng xác nhận.
2. **Luật suy luận nằm trong file dữ liệu (YAML/JSON), không hard-code trong Python.** Người dùng sẽ tự chỉnh luật.
3. **Mọi kết luận phải giải thích được:** mỗi giả thuyết kèm danh sách bằng chứng (dump nào, ngày giờ nào, module nào, event nào).
4. **Chấp nhận "không đủ dữ kiện".** Khi bằng chứng ít hoặc mâu thuẫn thì nói rõ. Không ép ra đáp án.
5. **Không dùng `ntoskrnl.exe`, `win32k.sys`, `hal.dll`, `ntfs.sys` làm kết luận "thủ phạm"** một cách mặc định. Đó thường chỉ là nơi phát hiện lỗi (nạn nhân). Phải tìm driver bên thứ ba trong stack trước (xem mục 7.3).
6. **Lõi tách khỏi giao diện.** Mọi chức năng phân tích phải chạy được bằng dòng lệnh (CLI) không cần GUI.
7. **Không phá hệ thống:** chỉ **đọc** dump và log. Không xoá, không sửa file gốc. Luôn **copy dump ra thư mục làm việc** rồi mới phân tích.
8. **Code dễ hiểu cho người không lập trình:** đặt tên rõ nghĩa, comment tiếng Việt, mỗi module có `README` ngắn. Cung cấp file `.bat` chạy một lần bấm (one-click).
9. **Xử lý lỗi mềm:** lỗi ở một nguồn dữ liệu (ví dụ không đọc được SMART) không được làm sập cả chương trình. Ghi cảnh báo và chạy tiếp.
10. **Không gửi dữ liệu ra ngoài** (dump có thể chứa mật khẩu/token). Chỉ được truy cập mạng để tải symbol Microsoft và (tuỳ chọn) tra cứu Bug Check online khi mã không có trong danh sách cục bộ.
11. **Ghi log chương trình** (file log xoay vòng) để dễ gỡ lỗi.
12. **Không tự thêm tính năng ngoài phạm vi.** Nếu thấy cần, ghi vào `docs/IDEAS.md` và hỏi.

---

## 2. CÔNG NGHỆ

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Ngôn ngữ | **Python 3.11+** | Xử lý text/regex/YAML nhanh, dễ sửa luật |
| Giao diện | **PySide6** (Qt) | Giao diện chuyên nghiệp, bảng dữ liệu tốt |
| Lưu trữ | **SQLite** (`sqlite3` có sẵn) | Nhẹ, không cần cài server, cache kết quả |
| Luật & dữ liệu | **YAML** (`PyYAML`) và JSON | Người dùng tự chỉnh |
| Test | **pytest** | Kiểm thử tự động |
| Đóng gói | **PyInstaller** | Ra 1 file `.exe` |
| Công cụ ngoài | **`cdb.exe`** (Windows Debugging Tools) | Phân tích dump chính xác (`!analyze -v`) |
| Báo cáo | HTML (Jinja2) và Excel (`openpyxl`) | Đính vào phiếu hỗ trợ |

Đường dẫn `cdb.exe` thường gặp (tự dò, cho phép người dùng chọn tay trong cấu hình):

```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe
```

Symbol path chuẩn:

```
srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

---

## 3. KIẾN TRÚC

```
Collectors  →  Dump Analyzer  →  Storage (SQLite)  →  Rule Engine  →  Report / GUI
```

### 3.1 Cấu trúc thư mục

```
DumpAnalyzer/
├── README.md
├── pyproject.toml
├── run_gui.bat                 # bấm đúp để mở giao diện
├── run_cli.bat                 # chạy dòng lệnh nhanh
├── config/
│   ├── settings.yaml           # đường dẫn cdb, symbol, thư mục làm việc, timeout...
│   ├── rules/
│   │   ├── bugcheck_rules.yaml # mã lỗi -> nhóm nghi ngờ + bước kiểm tra
│   │   ├── driver_map.yaml     # tên driver -> loại thiết bị + khuyến nghị
│   │   ├── event_rules.yaml    # event id/source -> ý nghĩa + trọng số
│   │   └── patterns.yaml       # luật mẫu hình qua nhiều dump
│   └── data/
│       └── bugcheck_codes.json # ~380 mã Bug Check của Microsoft
├── src/dumpanalyzer/
│   ├── core/
│   │   ├── models.py           # dataclass: Crash, Evidence, Finding
│   │   ├── config.py
│   │   ├── timeutil.py         # xử lý UTC / giờ địa phương
│   │   └── logging_setup.py
│   ├── collectors/
│   │   ├── dump_finder.py      # tìm file dump, copy ra thư mục làm việc, tính SHA256
│   │   ├── eventlog.py         # đọc Event Log theo khoảng thời gian
│   │   ├── hardware.py         # SMART, nhiệt độ, thông tin máy
│   │   └── drivers_updates.py  # driver đã cài, bản cập nhật, phần mềm mới cài
│   ├── analyzer/
│   │   ├── header_parser.py    # đọc header dump (dự phòng, không cần cdb)
│   │   ├── cdb_runner.py       # chạy cdb ngầm, timeout, song song, cache
│   │   └── cdb_parser.py       # đọc output của cdb thành dữ liệu có cấu trúc
│   ├── storage/
│   │   ├── db.py               # SQLite
│   │   └── schema.sql
│   ├── engine/
│   │   ├── rule_loader.py      # nạp & kiểm tra YAML
│   │   ├── correlator.py       # ghép dump với event theo thời gian
│   │   ├── scorer.py           # chấm điểm giả thuyết
│   │   └── verdict.py          # tạo kết luận + bước kiểm tra
│   ├── report/
│   │   ├── html_report.py
│   │   └── excel_report.py
│   ├── cli.py
│   └── gui/
│       └── (PySide6)
├── tests/
│   ├── fixtures/               # output cdb mẫu (.txt), dump nhỏ mẫu, event mẫu (.json)
│   └── test_*.py
└── docs/
    ├── ARCHITECTURE.md
    ├── RULES_GUIDE.md          # hướng dẫn người dùng tự sửa luật
    ├── TESTING_WITH_NOTMYFAULT.md
    └── IDEAS.md
```

### 3.2 Mô hình dữ liệu (SQLite)

```sql
CREATE TABLE machine (
  id INTEGER PRIMARY KEY,
  hostname TEXT, model TEXT, bios TEXT, cpu TEXT, os_build TEXT
);

CREATE TABLE crash (
  id INTEGER PRIMARY KEY,
  machine_id INTEGER REFERENCES machine(id),
  dump_path TEXT,              -- đường dẫn bản copy đã phân tích
  dump_sha256 TEXT UNIQUE,     -- khoá cache
  dump_type TEXT,              -- mini / kernel / full / none
  crash_time_utc TEXT,
  bugcheck_code TEXT,          -- ví dụ '0x124'
  p1 TEXT, p2 TEXT, p3 TEXT, p4 TEXT,
  image_name TEXT, module_name TEXT, process_name TEXT,
  failure_bucket_id TEXT,
  uptime_seconds INTEGER,
  cdb_raw_output TEXT,         -- LUÔN lưu output thô để phân tích lại khi đổi luật
  analyzed_by TEXT             -- 'cdb' hoặc 'header_only'
);

CREATE TABLE evidence (
  id INTEGER PRIMARY KEY,
  crash_id INTEGER REFERENCES crash(id),
  kind TEXT,                   -- dump / eventlog / smart / update / driver / thermal
  source TEXT,                 -- vd 'WHEA-Logger', 'Disk', 'cdb'
  event_id INTEGER,
  time_utc TEXT,
  summary TEXT,
  detail TEXT
);

CREATE TABLE finding (
  id INTEGER PRIMARY KEY,
  scope TEXT,                  -- 'crash' hoặc 'machine'
  crash_id INTEGER,
  machine_id INTEGER,
  suspect TEXT,                -- ram / storage / gpu / psu / thermal / cpu / driver:<tên> / update / unknown
  score REAL,                  -- 0..100
  confidence TEXT,             -- thấp / trung bình / cao
  rationale TEXT,
  evidence_ids TEXT,           -- danh sách id evidence, phân cách bằng dấu phẩy
  next_steps TEXT
);
```

---

## 4. LỘ TRÌNH THEO PHASE

> Mỗi Phase có: **Mục tiêu → Công việc → Sản phẩm → Tiêu chí nghiệm thu → Test**.
> Chỉ qua Phase sau khi người dùng xác nhận.

### PHASE 0 — Khảo sát & khung dự án

**Mục tiêu:** hiểu tài sản đã có, dựng khung dự án chạy được.

**Công việc**
1. Đọc mã nguồn công cụ Event Log hiện tại và danh sách Bug Check. Viết `docs/ARCHITECTURE.md` tóm tắt: cái gì tái sử dụng, cái gì viết lại.
2. Tạo cấu trúc thư mục ở mục 3.1, `pyproject.toml`, môi trường ảo, `pytest` chạy được.
3. Viết `config/settings.yaml` và bộ nạp cấu hình. Tự dò `cdb.exe`; nếu không có, báo hướng dẫn cài **Windows Debugging Tools** (một phần của Windows SDK).
4. Chuyển danh sách ~380 mã Bug Check sang `config/data/bugcheck_codes.json` (mã, tên, mô tả ngắn).
5. Thiết lập logging.

**Sản phẩm:** khung dự án, `run_cli.bat --version` chạy được, `docs/ARCHITECTURE.md`.

**Nghiệm thu:** `pytest` xanh (dù ít test); `python -m dumpanalyzer.cli check-env` in ra: phát hiện cdb hay chưa, quyền Administrator hay chưa, thư mục dump có tồn tại không.

---

### PHASE 1 — MVP dòng lệnh: thu dump & đọc thông tin cơ bản

**Mục tiêu:** liệt kê dump và đọc mã lỗi, không cần `cdb`.

**Công việc**
1. `dump_finder`: quét `C:\Windows\Minidump`, `C:\Windows\MEMORY.DMP`, `C:\Windows\LiveKernelReports`, hoặc thư mục tuỳ chọn. Copy ra thư mục làm việc, tính SHA256, bỏ qua file đã xử lý (cache).
2. `header_parser`: đọc trực tiếp header dump để lấy **mã BugCheck + 4 tham số + loại dump**. (Xem mục 7.1; **bắt buộc đối chiếu với `cdb` trên dump thật**, không tin mù quáng offset trong tài liệu này.)
3. Lưu vào bảng `crash`.
4. CLI: `dumpanalyzer scan --path <thư_mục> --from 2026-10-01 --to 2026-10-29` in bảng gồm: ngày giờ, mã lỗi, tên lỗi (tra `bugcheck_codes.json`), loại dump, đường dẫn.

**Sản phẩm:** lệnh `scan` chạy đúng, dữ liệu vào SQLite.

**Nghiệm thu**
- Trên **5–10 dump thật**, mã BugCheck và tham số **khớp 100%** với `WinDbg`/`cdb .bugcheck`.
- Chạy lại lần 2 không phân tích lại file đã có (cache theo SHA256).

**Test:** unit test header parser với 2–3 file dump nhỏ mẫu trong `tests/fixtures/`.

---

### PHASE 2 — Tích hợp `cdb`: phân tích sâu

**Mục tiêu:** lấy thủ phạm, stack, module, process từ `!analyze -v`.

**Công việc**
1. `cdb_runner`: chạy lệnh dưới đây với **timeout** (mặc định 300 giây), chạy song song tối đa 2–4 tiến trình (cấu hình được), ghi output ra file, lưu output thô vào `crash.cdb_raw_output`.

```bash
cdb.exe -z "<dump>" -y "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols" -c "!analyze -v; .bugcheck; vertarget; .time; kv; lm t n; q" -logo "<out.txt>"
```

2. `cdb_parser`: dùng regex đọc các trường: `BUGCHECK_CODE`, `BUGCHECK_P1..P4`, `IMAGE_NAME`, `MODULE_NAME`, `FAILURE_BUCKET_ID`, `PROCESS_NAME`, `STACK_TEXT`, uptime, thời gian sập, bản Windows, danh sách module (từ `lm t n`) kèm timestamp. Trích riêng danh sách **module bên thứ ba có trong stack**.
3. Lệnh bổ sung theo mã lỗi (cấu hình trong `bugcheck_rules.yaml`, trường `extra_cdb`):
   - `0x124`: `!errrec <P2>`
   - `0x133`: `!dpcs` và `!timer`
   - `0xD1`, `0xA`, `0xC4`: `!irp`, `!devstack` khi có địa chỉ phù hợp
   - `0x1A`, `0x50`, `0xC2`: `!vm`, `!poolused 2`
4. Nếu `cdb` lỗi/timeout/không có symbol: **fallback về `header_only`**, đánh dấu rõ trong `analyzed_by`.
5. Cho phép **tải symbol trước** bằng lệnh riêng (`dumpanalyzer warmup-symbols`) để tránh treo khi phân tích hàng loạt.

**Sản phẩm:** `dumpanalyzer analyze --all` phân tích mọi dump chưa xử lý.

**Nghiệm thu:** trên 5–10 dump thật, `IMAGE_NAME`, `MODULE_NAME`, `FAILURE_BUCKET_ID` khớp với kết quả `WinDbg Preview` làm bằng tay. Dump lỗi/hỏng không làm sập cả đợt chạy.

**Test:** lưu 8–10 file output `!analyze -v` mẫu làm `fixtures`, test `cdb_parser` **không cần cdb thật**. Phải có case: dump không rõ thủ phạm (`ntoskrnl` chung chung), dump có driver bên thứ ba, output thiếu trường.

---

### PHASE 3 — Thu thập Event Log & ngữ cảnh hệ thống, ghép theo thời gian

**Mục tiêu:** có đủ bằng chứng ngoài dump.

**Công việc**
1. `eventlog`: đọc System log theo khoảng thời gian (tái sử dụng logic công cụ cũ). Các nguồn cần quan tâm (cấu hình trong `event_rules.yaml`):

| Nguồn / Event | Ý nghĩa |
|---|---|
| `Microsoft-Windows-Kernel-Power` 41 | Tắt/khởi động lại không sạch; **đọc trường `BugcheckCode`** (0 nghĩa là không có BSOD, nghi mất nguồn/treo cứng) |
| `EventLog` 6008 | Lần tắt trước không bình thường |
| `BugCheck` (WER-SystemErrorReporting) 1001 | Có đường dẫn dump và mã lỗi |
| `Microsoft-Windows-WHEA-Logger` 1, 17, 18, 19, 20, 47 | Lỗi phần cứng (CPU/PCIe/RAM) |
| `Disk` 7, 11, 51, 153 | Lỗi ổ đĩa |
| `storahci`/`stornvme` 129 | Reset thiết bị lưu trữ |
| `Ntfs` 55 | Hỏng hệ thống tệp |
| `Display` 4101, `nvlddmkm` 14 | Driver card đồ họa phục hồi/lỗi |
| `volmgr` 161 / 162 | Tạo dump thất bại / thành công |
| `WindowsUpdateClient` 19, 20 | Cập nhật cài thành công/thất bại |
| `MsiInstaller` 11707, 1033 | Cài phần mềm |
| `User32` 1074 | Tắt/khởi động lại có chủ đích (loại trừ) |

2. `hardware`: SMART qua `Get-PhysicalDisk` và `Get-StorageReliabilityCounter`, nhiệt độ nếu đọc được, thông tin máy (model, BIOS, CPU, RAM).
3. `drivers_updates`: danh sách driver (`Win32_PnPSignedDriver`: tên, hãng, phiên bản, **ngày driver**), các bản cập nhật và phần mềm cài trong 30 ngày gần nhất, driver chưa ký.
4. `correlator`: với mỗi crash lấy các event trong **cửa sổ 10 phút trước thời điểm sập** (cấu hình được), thêm sự kiện **cập nhật/cài đặt trong 7 ngày trước lần sập đầu tiên**. Lưu vào bảng `evidence`.
5. **Múi giờ:** dump thường ghi UTC, Event Log hiển thị giờ địa phương. Chuẩn hoá **tất cả về UTC** khi lưu, chỉ đổi sang giờ địa phương khi hiển thị (`timeutil.py`). Có test riêng cho phần này.
6. Trường hợp **không có dump** (Kernel-Power 41 với `BugcheckCode = 0`): vẫn tạo bản ghi crash loại `none`, để Rule Engine xử lý nhóm nghi ngờ nguồn/quá nhiệt/treo cứng.

**Nghiệm thu:** với mỗi crash, xem được danh sách sự kiện 10 phút trước đó; lệch múi giờ bằng 0 (kiểm tra bằng một lần sập đã biết giờ).

---

### PHASE 4 — Rule Engine: chấm điểm & kết luận

**Mục tiêu:** xuất kết luận có điểm tin cậy, bằng chứng, hành động kiểm tra.

**Công việc**
1. `rule_loader`: nạp và **kiểm tra cú pháp** các file YAML, báo lỗi rõ ràng kèm số dòng. Có lệnh `dumpanalyzer validate-rules`.
2. Viết bộ luật khởi đầu (xem mục 5).
3. `scorer`: thuật toán chấm điểm (xem mục 6).
4. `verdict`: sinh kết luận từng crash và kết luận tổng hợp theo máy; mỗi kết luận kèm bằng chứng và các bước kiểm tra theo thứ tự **dễ → khó**.
5. CLI: `dumpanalyzer verdict --machine <tên> --from ... --to ...`.

**Nghiệm thu**
- Với bộ dump tạo bằng **NotMyFault** (mục 8), kết luận đúng nhóm trong ≥ 80% trường hợp.
- Mọi kết luận đều có `evidence_ids`.
- Trường hợp chỉ có 1 dump: độ tin cậy **tối đa "trung bình"**.
- Khi dump và log mâu thuẫn: hiển thị cảnh báo "chưa thống nhất".

---

### PHASE 5 — Giao diện (PySide6)

**Mục tiêu:** người dùng không lập trình dùng được ngay.

**Chức năng**
1. Chọn nguồn: máy cục bộ hoặc thư mục dump đã thu về.
2. Chọn khoảng thời gian (từ ngày giờ – đến ngày giờ), nút **Phân tích**.
3. Thanh tiến trình, nút Huỷ, không làm đơ giao diện (chạy nền bằng `QThread`/`QThreadPool`).
4. Tab **Tổng quan:** bảng crash (ngày giờ theo giờ địa phương, mã lỗi, tên lỗi, module, nhóm nghi ngờ). Lọc/sắp xếp được.
5. Tab **Chi tiết crash:** thông tin dump, stack, module bên thứ ba, event 10 phút trước.
6. Tab **Kết luận:** xếp hạng nghi ngờ (ví dụ "GPU driver 85%, RAM 10%…"), bằng chứng bấm vào xem được, **các bước kiểm tra theo thứ tự**.
7. Tab **Cài đặt:** đường dẫn cdb, symbol, thư mục làm việc, cửa sổ thời gian, số tiến trình song song.
8. Xuất báo cáo HTML/Excel.
9. Thông báo thân thiện bằng tiếng Việt khi thiếu cdb, thiếu quyền Admin, dump hỏng.

**Nghiệm thu:** một kỹ thuật viên khác dùng được không cần hướng dẫn; giao diện không treo khi phân tích 50 dump.

---

### PHASE 6 — Phân tích nhiều dump / nhiều máy & đóng gói

**Công việc**
1. Phân tích mẫu hình qua nhiều dump (luật `patterns.yaml`): lặp module, nhiều module khác nhau, thời điểm liên quan cập nhật.
2. Nhập dump từ nhiều máy (mỗi máy một thư mục con, tên thư mục là tên máy); thống kê theo máy và model: phát hiện driver/model gây lỗi hàng loạt.
3. Xuất báo cáo tổng hợp (HTML/Excel).
4. Đóng gói bằng PyInstaller thành `.exe`, kèm `config/` bên cạnh để người dùng sửa luật.
5. Hướng dẫn `docs/RULES_GUIDE.md` (cách thêm một driver, một mã lỗi, một mẫu hình — có ví dụ).
6. Dọn dẹp bảo mật: tuỳ chọn tự xoá bản copy dump sau khi phân tích; thư mục làm việc có phân quyền.

**Nghiệm thu:** bản `.exe` chạy được trên máy sạch (chỉ cần có `cdb` nếu muốn phân tích sâu); báo cáo tổng hợp đúng với dữ liệu mẫu.

---

## 5. BỘ LUẬT KHỞI ĐẦU

### 5.1 `bugcheck_rules.yaml` (mẫu, mở rộng thêm theo nhóm)

```yaml
# Điểm là trọng số ban đầu (prior) cho từng nhóm nghi ngờ, tổng không cần bằng 100
0x124:
  name: WHEA_UNCORRECTABLE_ERROR
  suspects: {cpu: 40, ram: 30, psu: 20, thermal: 10}
  extra_cdb: ["!errrec {p2}"]
  next_steps:
    - Kiểm tra nhiệt độ CPU và quạt tản nhiệt
    - Chạy MemTest86 (ít nhất 2 lượt)
    - Thử nguồn khác hoặc kiểm tra điện áp
    - Cập nhật BIOS

0x133:
  name: DPC_WATCHDOG_VIOLATION
  suspects: {driver: 50, storage: 30, cpu: 10, gpu: 10}
  extra_cdb: ["!dpcs", "!timer"]
  next_steps:
    - Cập nhật firmware SSD và driver chipset/lưu trữ
    - Gỡ driver bên thứ ba vừa cài gần đây

0x1A:
  name: MEMORY_MANAGEMENT
  suspects: {ram: 55, driver: 25, storage: 20}
  extra_cdb: ["!vm", "!poolused 2"]
  next_steps:
    - Chạy MemTest86
    - Thử từng thanh RAM riêng
    - Kiểm tra SMART ổ đĩa (pagefile)
# ... bổ sung các mã: 0x50, 0x3B, 0xA, 0xD1, 0xC4, 0xC9, 0x7A, 0x7B, 0xF4, 0x116, 0x117, 0x119, 0x9F, 0x101, 0x139, 0xEF, 0x1E, 0x24, 0x23...
```

Nhóm gợi ý để điền nốt:

| Mã | Nhóm nghi ngờ chính |
|---|---|
| 0x1A, 0x4E, 0x50, 0x12E, 0xC2 | RAM hoặc driver hỏng bộ nhớ |
| 0x7A, 0x7B, 0xF4, 0x24, 0x23 | Ổ cứng/SSD, cáp, controller |
| 0xD1, 0xA, 0xC4, 0xC9, 0x3B | Driver lỗi (xem `IMAGE_NAME` và stack) |
| 0x116, 0x117, 0x119 | Card đồ họa / driver GPU |
| 0x9F | Quản lý nguồn, driver không thoát sleep |
| 0x101 | Treo CPU/driver, firmware |
| 0xEF, 0x139, 0x1E | Tiến trình/driver hệ thống, phần mềm bảo mật |

### 5.2 `driver_map.yaml` (mẫu)

```yaml
nvlddmkm.sys:  {device: "GPU NVIDIA",  type: gpu,     action: "Gỡ sạch bằng DDU rồi cài lại driver sạch"}
amdkmdag.sys:  {device: "GPU AMD",     type: gpu,     action: "Cài lại driver từ trang AMD"}
igdkmd64.sys:  {device: "GPU Intel",   type: gpu,     action: "Cập nhật driver đồ hoạ Intel"}
stornvme.sys:  {device: "SSD NVMe",    type: storage, action: "Cập nhật firmware SSD, kiểm tra SMART"}
storahci.sys:  {device: "SATA/AHCI",   type: storage, action: "Kiểm tra cáp, SMART, driver chipset"}
rt640x64.sys:  {device: "Card mạng Realtek", type: network, action: "Cập nhật/cài lại driver mạng"}
# người dùng sẽ tự bổ sung thêm
ms_core_modules:   # module Microsoft: chỉ là nạn nhân, KHÔNG kết luận thủ phạm
  - ntoskrnl.exe
  - ntkrnlmp.exe
  - win32k.sys
  - win32kfull.sys
  - win32kbase.sys
  - hal.dll
  - ntfs.sys
  - fltmgr.sys
```

### 5.3 `patterns.yaml` (mẫu)

```yaml
- name: Module khác nhau mỗi lần, toàn module Microsoft
  when: {min_dumps: 3, distinct_modules_min: 3, only_microsoft_modules: true}
  add: {ram: 30, psu: 20, thermal: 10}
  note: "Dấu hiệu phần cứng: RAM, nguồn hoặc nhiệt"

- name: Cùng một driver bên thứ ba lặp lại
  when: {min_dumps: 3, same_third_party_module_min: 3}
  add: {driver_of_module: 40}

- name: Lỗi bắt đầu sau cập nhật/cài đặt
  when: {first_crash_within_days_after_update: 7}
  add: {update: 25}
  next_steps: ["Gỡ bản cập nhật hoặc rollback driver đó"]

- name: Có Kernel-Power 41, BugcheckCode = 0, không có dump
  when: {no_dump: true, kernelpower41_bugcheck0: true}
  add: {psu: 35, thermal: 30, cpu: 10}
```

### 5.4 `event_rules.yaml` (mẫu)

```yaml
- {source: "Microsoft-Windows-WHEA-Logger", ids: [1, 17, 18, 19, 20, 47], adds: {cpu: 15, ram: 10, psu: 5}}
- {source: "Disk", ids: [7, 11, 51, 153], adds: {storage: 20}}
- {source: "stornvme", ids: [129], adds: {storage: 20}}
- {source: "Display", ids: [4101], adds: {gpu: 20}}
- {source: "nvlddmkm", ids: [14], adds: {gpu: 20}}
- {source: "Ntfs", ids: [55], adds: {storage: 15}}
```

---

## 6. THUẬT TOÁN CHẤM ĐIỂM (đặc tả)

**Cho từng crash:**
1. Điểm khởi đầu từ `bugcheck_rules.yaml` (nhóm nghi ngờ theo mã lỗi).
2. Nếu `IMAGE_NAME`/module bên thứ ba có trong `driver_map.yaml` → cộng điểm cho nhóm thiết bị tương ứng (ưu tiên khi module nằm trong **stack của luồng gây lỗi**).
3. Nếu `IMAGE_NAME` là module Microsoft (`ms_core_modules`) → **không cộng điểm cho driver đó**; tìm module bên thứ ba trong stack. Nếu không có, cộng nhẹ cho nhóm phần cứng theo mã lỗi.
4. Cộng điểm từ event trong cửa sổ trước khi sập theo `event_rules.yaml`. Event **cùng nhóm** với giả thuyết từ dump được nhân hệ số 1.5 (đồng thuận).
5. Chuẩn hoá về thang 0–100 trên tổng các nhóm.

**Cho từng máy (nhiều crash):**
1. Tổng hợp điểm các crash; áp dụng `patterns.yaml`.
2. **Thưởng lặp lại:** cùng một giả thuyết xuất hiện ở ≥ 3 crash thì tăng hệ số (cấu hình được).
3. **Trần độ tin cậy:** 1 crash → tối đa "trung bình"; có dump nhưng không phân tích được bằng `cdb` (`header_only`) → tối đa "trung bình".
4. **Phát hiện mâu thuẫn:** nếu giả thuyết đứng đầu theo dump khác giả thuyết đứng đầu theo log và chênh nhau < 15 điểm → gắn cờ "chưa thống nhất".
5. **Độ tin cậy:** cao ≥ 70, trung bình 40–69, thấp < 40 (ngưỡng nằm trong `settings.yaml`).
6. Nếu điểm cao nhất < 35 → kết luận **"không đủ dữ kiện"** kèm danh sách dữ liệu nên thu thêm.

**Đầu ra mỗi giả thuyết:** `suspect`, `score`, `confidence`, `rationale` (1–3 câu tiếng Việt), `evidence_ids`, `next_steps`.

---

## 7. CHI TIẾT KỸ THUẬT QUAN TRỌNG

### 7.1 Header dump (dự phòng, không cần cdb)

- Dump kernel/complete trên Windows 64-bit có header `PAGEDU64` (cấu trúc `DMP_HEADER64`): chữ ký `PAGE` `DU64` ở đầu file.
- Các trường cần đọc (theo hiểu biết hiện tại, **bắt buộc xác minh bằng dump thật và `cdb .bugcheck`**): `BugCheckCode` ở offset `0x38`, `BugCheckParameter1..4` ở `0x40, 0x48, 0x50, 0x58`.
- Một số minidump dùng định dạng khác (`MDMP`). Parser phải **nhận dạng chữ ký** và báo "định dạng chưa hỗ trợ" thay vì đọc bừa.
- Nếu header parser và `cdb` cho kết quả khác nhau → **tin `cdb`**, ghi cảnh báo.

### 7.2 Chạy `cdb`

- Dùng `subprocess` với danh sách tham số (không ghép chuỗi shell), có `timeout`, bắt `stdout/stderr`, mã thoát.
- Một dump mỗi tiến trình; giới hạn số tiến trình song song.
- Lần đầu tải symbol rất chậm → hiển thị cảnh báo; có thư mục cache symbol cố định.
- Cần quyền Administrator để đọc `C:\Windows\Minidump` và `MEMORY.DMP`; kiểm tra và báo rõ nếu thiếu.

### 7.3 Phân biệt thủ phạm và nạn nhân

Quy trình: `IMAGE_NAME` → nếu thuộc `ms_core_modules` thì tìm trong `STACK_TEXT` các module **không thuộc Microsoft** → kiểm tra `lm t n` xem hãng, phiên bản, ngày biên dịch → driver rất cũ hoặc vừa cập nhật gần ngày lỗi đầu tiên là dấu hiệu mạnh.

### 7.4 Bảo mật & quyền riêng tư

- Dump chứa nội dung bộ nhớ (có thể có mật khẩu/token). Không upload đi đâu. Thư mục làm việc dùng quyền hạn chế.
- Có tuỳ chọn xoá bản copy dump sau khi phân tích; không bao giờ xoá file gốc.

---

## 8. KIỂM THỬ

1. **Dùng máy ảo VMware**, không dùng máy thật của người dùng.
2. Dùng **NotMyFault** (Sysinternals) gây BSOD theo từng kiểu: lỗi pool, IRQL, driver, treo hệ thống... để thu dump có nguyên nhân đã biết.
3. Lưu dump nhỏ và output `!analyze -v` vào `tests/fixtures/` làm **golden file**.
4. Test đơn vị cho: header parser, cdb parser (không cần cdb thật), rule loader (YAML sai phải báo lỗi rõ), correlator (múi giờ), scorer (các ca: 1 dump, nhiều dump cùng module, nhiều dump khác module, mâu thuẫn, không dump).
5. **Đối chiếu bằng tay** 5–10 dump đầu với `WinDbg Preview`.
6. Viết `docs/TESTING_WITH_NOTMYFAULT.md` hướng dẫn từng bước cho người không lập trình.

---

## 9. ĐỊNH NGHĨA HOÀN THÀNH (Definition of Done) CẢ DỰ ÁN

- [ ] Phase 0–6 đều qua nghiệm thu và được người dùng xác nhận.
- [ ] Phân tích được dump thật và cho kết luận kèm bằng chứng.
- [ ] Sửa luật bằng file YAML mà không cần sửa code; `validate-rules` báo lỗi rõ ràng.
- [ ] Có file `.bat` một lần bấm và bản `.exe`.
- [ ] `pytest` xanh; có golden file.
- [ ] Có `README.md`, `RULES_GUIDE.md`, `TESTING_WITH_NOTMYFAULT.md` bằng tiếng Việt.
- [ ] Không có đường dẫn, tên máy hay dữ liệu thật của công ty bị hard-code trong code.

---

## 10. PROMPT BÀN GIAO CHO ANTIGRAVITY

### 10.1 Prompt chính (dán vào đầu dự án)

```text
VAI TRÒ
Bạn là kỹ sư phần mềm cấp cao, chuyên về Windows internals và công cụ chẩn đoán. Bạn đang xây dựng "DumpAnalyzer" cho một nhân viên IT KHÔNG có nền tảng lập trình. Vì vậy code phải dễ đọc, có comment tiếng Việt, dễ chạy (một lần bấm), và dễ chỉnh luật bằng file YAML.

NGUỒN SỰ THẬT
Đọc toàn bộ file ANTIGRAVITY_HANDOFF_DumpAnalyzer.md trong repo trước khi làm bất cứ việc gì. File đó quy định mục tiêu, kiến trúc, 7 Phase (0–6), tiêu chí nghiệm thu, đặc tả thuật toán chấm điểm và bộ luật khởi đầu. Nếu có mâu thuẫn giữa yêu cầu của tôi trong chat và file đó, hãy hỏi lại tôi, đừng tự chọn.

MỤC TIÊU
Phần mềm đọc và phân tích file dump (màn hình xanh/BSOD) kết hợp Event Log để khoanh vùng nguyên nhân gây lỗi/tự khởi động lại, rồi đưa ra kết luận có điểm tin cậy, bằng chứng cụ thể và các bước kiểm tra theo thứ tự từ dễ đến khó. Trọng tâm là PHÂN TÍCH DUMP; log là bằng chứng bổ trợ.

TÀI SẢN CÓ SẴN
(1) Công cụ Event Log hiện tại (PowerShell + .bat, đã có giao diện) — hãy đọc và tái sử dụng logic phù hợp.
(2) Danh sách ~380 mã Bug Check của Microsoft.
Nếu không tìm thấy hai thứ này trong repo, DỪNG và hỏi tôi. Không được tự bịa dữ liệu.

CÔNG NGHỆ
Python 3.11+, PySide6, SQLite, PyYAML, pytest, PyInstaller. Phân tích dump bằng cdb.exe (Windows Debugging Tools) chạy ngầm với `!analyze -v`, có fallback đọc header dump nếu không có cdb.

QUY TRÌNH LÀM VIỆC (BẮT BUỘC)
1. Chỉ làm MỘT Phase mỗi lần, đúng thứ tự Phase 0 → 6.
2. Trước khi code mỗi Phase: viết kế hoạch ngắn (file nào sẽ tạo/sửa, rủi ro, câu hỏi còn thiếu) và chờ tôi đồng ý nếu có điểm chưa rõ.
3. Sau khi code mỗi Phase: chạy test, rồi báo cáo gồm (a) đã làm gì, (b) cách chạy thử bằng lệnh cụ thể, (c) kết quả test, (d) những gì chưa chắc chắn, (e) đối chiếu từng tiêu chí nghiệm thu. Sau đó DỪNG và chờ tôi xác nhận trước khi sang Phase kế.
4. Không thêm tính năng ngoài phạm vi. Ý tưởng mới ghi vào docs/IDEAS.md rồi hỏi tôi.

QUY TẮC KỸ THUẬT KHÔNG ĐƯỢC VI PHẠM
- Luật suy luận nằm trong file YAML/JSON (config/rules/*), KHÔNG hard-code trong Python.
- Lõi (collectors, analyzer, storage, engine) chạy được bằng CLI không cần GUI. GUI chỉ gọi lõi.
- Mọi kết luận phải kèm evidence_ids truy ngược được về dump/event cụ thể.
- Cho phép kết quả "không đủ dữ kiện" và gắn cờ "chưa thống nhất" khi dump và log mâu thuẫn. Một dump đơn lẻ thì độ tin cậy tối đa "trung bình".
- Module Microsoft (ntoskrnl.exe, win32k*.sys, hal.dll, ntfs.sys...) KHÔNG phải thủ phạm mặc định. Phải tìm driver bên thứ ba trong stack trước.
- Lưu output thô của cdb vào SQLite để phân tích lại khi đổi luật, không chạy lại cdb.
- Cache theo SHA256 của dump; không phân tích lại file đã xử lý.
- Chuẩn hoá mọi thời gian về UTC khi lưu; chỉ đổi sang giờ địa phương khi hiển thị. Có test cho phần này.
- Chỉ ĐỌC dump và log; luôn copy dump ra thư mục làm việc rồi mới phân tích; không bao giờ xoá/sửa file gốc.
- Dùng subprocess với danh sách tham số (không ghép chuỗi shell), có timeout; một lỗi ở một nguồn dữ liệu không được làm sập cả chương trình.
- Không gửi dữ liệu dump ra ngoài. Mạng chỉ dùng để tải symbol Microsoft (và tuỳ chọn tra cứu Bug Check online khi mã thiếu trong danh sách cục bộ).
- Offset trong header dump ở file handoff cần được XÁC MINH bằng dump thật và `cdb .bugcheck`. Nếu khác nhau thì tin cdb và báo cho tôi.
- Mọi thông báo cho người dùng bằng tiếng Việt, rõ ràng, nói được cần làm gì tiếp theo (ví dụ: thiếu cdb thì hướng dẫn cài Windows Debugging Tools).

KIỂM THỬ
Viết pytest cho từng module. Dùng fixture là output `!analyze -v` mẫu để test parser mà không cần cdb. Hướng dẫn tôi tạo dump thử trên máy ảo VMware bằng NotMyFault và đối chiếu bằng WinDbg Preview. Không bao giờ khẳng định "đã chạy đúng" nếu chưa chạy test hoặc chưa kiểm chứng.

TRUNG THỰC
Nếu không chắc về một chi tiết kỹ thuật (offset header, cú pháp lệnh cdb, tên event), hãy nói rõ là chưa chắc và đề xuất cách kiểm chứng. Không đoán rồi trình bày như sự thật.

BẮT ĐẦU
Hãy bắt đầu với PHASE 0: (1) đọc tài sản có sẵn trong repo và file handoff, (2) viết bản tóm tắt docs/ARCHITECTURE.md nêu rõ cái gì tái sử dụng, cái gì viết mới, (3) liệt kê các câu hỏi bạn cần tôi trả lời, (4) chờ tôi xác nhận rồi mới dựng khung dự án.
```

### 10.2 Prompt ngắn cho từng Phase (dùng sau khi người dùng xác nhận Phase trước)

**Phase 1**
```text
Bắt đầu PHASE 1 theo file handoff (mục 4). Làm dump_finder, header_parser, lưu vào bảng crash, lệnh `scan`. Nhớ: xác minh offset header bằng cdb trên dump thật; cache theo SHA256. Khi xong, báo cáo theo quy trình và đối chiếu từng tiêu chí nghiệm thu, rồi dừng.
```

**Phase 2**
```text
Bắt đầu PHASE 2. Làm cdb_runner (timeout, song song, cache, lưu output thô), cdb_parser, lệnh bổ sung theo mã lỗi, fallback header_only, lệnh warmup-symbols. Viết test cho parser bằng fixture output !analyze -v (gồm ca ntoskrnl chung chung, ca có driver bên thứ ba, ca thiếu trường). Xong thì báo cáo và dừng.
```

**Phase 3**
```text
Bắt đầu PHASE 3. Làm eventlog (tái sử dụng logic công cụ cũ), hardware (SMART, thông tin máy), drivers_updates, correlator (cửa sổ 10 phút trước khi sập, cập nhật 7 ngày trước), xử lý múi giờ UTC, ca không có dump (Kernel-Power 41 với BugcheckCode = 0). Test múi giờ riêng. Xong thì báo cáo và dừng.
```

**Phase 4**
```text
Bắt đầu PHASE 4. Làm rule_loader (báo lỗi YAML kèm số dòng, lệnh validate-rules), bộ luật khởi đầu theo mục 5, scorer theo đặc tả mục 6, verdict kèm bằng chứng và bước kiểm tra. Test đủ các ca: 1 dump, nhiều dump cùng module, khác module, mâu thuẫn, không dump. Xong thì báo cáo và dừng.
```

**Phase 5**
```text
Bắt đầu PHASE 5. Làm giao diện PySide6 theo mục 4 (Phase 5): chọn nguồn, khoảng thời gian, chạy nền không đơ giao diện, các tab Tổng quan/Chi tiết/Kết luận/Cài đặt, xuất báo cáo. Giao diện chỉ gọi lõi, không chứa logic phân tích. Thông báo lỗi thân thiện bằng tiếng Việt. Xong thì báo cáo và dừng.
```

**Phase 6**
```text
Bắt đầu PHASE 6. Làm phân tích mẫu hình nhiều dump, nhập dữ liệu nhiều máy, báo cáo tổng hợp, đóng gói PyInstaller kèm thư mục config, viết RULES_GUIDE.md và TESTING_WITH_NOTMYFAULT.md. Chạy toàn bộ checklist Definition of Done (mục 9) và báo cáo từng mục.
```

---

## 11. ĐIỀU NGƯỜI DÙNG CẦN CHUẨN BỊ TRƯỚC KHI CHẠY ANTIGRAVITY

1. Mã nguồn công cụ Event Log hiện tại và danh sách ~380 mã Bug Check, đặt vào repo.
2. Cài **Windows Debugging Tools** (qua Windows SDK) trên máy IT để có `cdb.exe`.
3. Một vài file dump thật (5–10 file) và/hoặc output `!analyze -v` thật để làm fixture.
4. Máy ảo VMware + **NotMyFault** để tạo dump thử.
5. Quyền Administrator trên máy chạy công cụ.
