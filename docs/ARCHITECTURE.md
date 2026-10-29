# DumpAnalyzer — Tài liệu Kiến trúc & Khảo sát Tài sản

> Tài liệu này là bản tổng hợp kiến trúc hệ thống, được cập nhật sau khi tiếp nhận **Tài liệu Bổ sung Đợt 1 (UPDATE_01)**.
> Nguyên tắc ưu tiên: Nếu có mâu thuẫn giữa handoff gốc và UPDATE_01, nội dung UPDATE_01 được ưu tiên.

---

## 1. Khảo sát Tài sản Sẵn có

Trong quá trình khởi tạo dự án, hai tài sản nền tảng đã được khảo sát và lưu vết trong repo:

| STT | Tài sản | Vị trí lưu trữ trong repo | Mô tả & Hiện trạng |
| :--- | :--- | :--- | :--- |
| **1** | **Công cụ Event Log hiện tại** | `legacy_tools/EventLogAnalyzer.ps1`<br>`legacy_tools/Chay-EventLogAnalyzer.bat` | Script PowerShell (~1.740 dòng) có GUI WinForms, lọc 34 curated events, gom cụm incident và phân loại nhóm nguyên nhân. |
| **2** | **Danh sách mã Bug Check Microsoft** | `config/data/bugcheck_codes.json` | Đầy đủ **380 mã Bug Check** chuẩn của Microsoft (từ `0x1 APC_INDEX_MISMATCH` đến `0xDEADDEAD MANUALLY_INITIATED_CRASH1`), có tên chuẩn tiếng Anh và phân nhóm gợi ý. |

---

## 2. Kế hoạch Tái sử dụng vs. Viết mới

### 2.1 Thành phần Tái sử dụng & Chuyển đổi (Reuse & Transform)

1. **Dữ liệu 380 mã Bug Check:**
   - Đã chuẩn hoá thành file JSON `config/data/bugcheck_codes.json` tra cứu O(1) theo mã Hex.
2. **Logic Phân loại mã Bug Check (`Get-BugCheckGroupFromName`):**
   - Đã chuyển đổi thành các quy tắc khai báo trong `config/rules/bugcheck_rules.yaml`.
3. **Danh mục sự kiện Event Log trọng yếu & Trọng số suy luận:**
   - Chuyển thành `config/rules/event_rules.yaml` với cơ chế tính điểm trọng số `adds` và ngưỡng chặn `cap`.
   - **Bổ sung từ UPDATE_01:** Đọc Event 41 lấy `BugcheckCode` dạng số thập phân và đổi sang Hex; `BugcheckCode = 0` nghĩa là sập nguồn/treo cứng không có BSOD. Đọc bằng XML theo tên trường dữ liệu.
4. **Nguyên lý tương quan thời gian (Incident Correlation):**
   - Ghép sự kiện trong cửa sổ 10 phút trước khi sập; lịch sử cập nhật/driver 7 ngày trước crash đầu tiên.
   - Gộp Event 41 và Event 1001 của cùng một lần sập (cách nhau vài giây/phút) thành **một crash duy nhất**.

---

### 2.2 Thành phần Viết mới Hoàn toàn (New Development)

1. **Bộ kiểm tra khả năng ghi dump (Phase 1B — Bổ sung từ UPDATE_01):**
   - Lệnh `dumpanalyzer check-dump-config`:
     + **Mặc định CHỈ ĐỌC:** Kiểm tra registry `CrashDumpEnabled`, `AutoReboot`, `Overwrite`, `MinidumpDir`, `DumpFile`.
     + Kiểm tra Pagefile trên ổ chứa Windows (`Win32_PageFileUsage`), cảnh báo nếu thiếu.
     + Kiểm tra dung lượng trống ổ đĩa chứa Windows (`Win32_LogicalDisk`), so sánh với RAM.
     + Kiểm tra lịch sử `volmgr` 161 (ghi dump thất bại) / 162 (thành công).
     + Trả về trạng thái máy: **Sẵn sàng / Cần chú ý / Không ghi được dump**.
   - Chế độ `--apply`:
     + Chỉ kích hoạt khi có tham số `--apply` VÀ người dùng xác nhận trực tiếp bằng tay.
     + **Sao lưu registry cũ** vào file `backup/CrashControl_<hostname>_<thời_gian>.reg` hoặc JSON.
     + Chỉ đặt `CrashDumpEnabled = 7` (Automatic memory dump). Không sửa pagefile, không tự khởi động lại máy.
     + Ghi log đầy đủ mọi thay đổi.
2. **Chế độ "Chỉ Log" khi không có dump (`log_only` — Bổ sung từ UPDATE_01):**
   - Máy tắt ghi dump hoặc sập đột ngột không kịp ghi dump $\rightarrow$ Tạo bản ghi `crash` loại `none`, `analyzed_by = 'log_only'`.
   - **Quy tắc suy luận:** Chỉ kết luận NHÓM thiết bị (GPU, RAM, lưu trữ, nguồn/nhiệt), **tuyệt đối không kết luận driver cụ thể** (trừ phi Event Log tự nêu rõ tên driver trong log).
   - Giao diện và báo cáo gắn nhãn rõ ràng: **"Không có dump – kết luận kém chắc chắn"**.
   - Bổ sung bước kiểm tra đầu tiên: **Khuyến nghị bật ghi dump**.
3. **Bộ phân tích Header Dump không cần cdb (`header_parser.py`):**
   - Đọc nhị phân header `PAGEDU64`, `DMP_HEADER64`, nhận diện `MDMP`.
   - Trích xuất BugCheckCode và 4 tham số. Đối chiếu kiểm chứng với `cdb .bugcheck` trên dump thật.
4. **Bộ điều phối CDB Runner & Parser (`cdb_runner.py`, `cdb_parser.py`):**
   - Chạy `cdb.exe` ngầm an toàn qua danh sách đối số, có timeout 300s, phân tích stack, module.
   - Tuân thủ nguyên tắc: **Không bao giờ coi module Microsoft (`ntoskrnl.exe`, `hal.dll`, `win32k*.sys`...) là thủ phạm mặc định**.
5. **Lưu trữ CSDL SQLite & Cache SHA256 (`storage/`):**
   - Bảng `machine`, `crash`, `evidence`, `finding`. Cache theo SHA256 file dump. Lưu trọn vẹn `cdb_raw_output`.
6. **Xử lý Thời gian Chuẩn hoá UTC (`core/timeutil.py`):**
   - Lưu trữ và tính toán 100% bằng UTC ISO-8601; chỉ chuyển đổi sang giờ địa phương khi hiển thị.
7. **Quy tắc Trần Độ Tin Cậy Mới (Cập nhật theo UPDATE_01):**
   - Có dump phân tích bằng `cdb`: 1 crash tối đa "trung bình"; nhiều crash có thể đạt "cao".
   - Phân tích bằng `header_only`: Tối đa "trung bình".
   - `log_only` có mã Bug Check $\neq$ 0 VÀ có event hỗ trợ cùng hướng: Tối đa "trung bình".
   - `log_only` có mã Bug Check nhưng không có event hỗ trợ: Tối đa "thấp".
   - `log_only` với `BugcheckCode = 0` (mất nguồn/treo cứng): Tối đa "thấp".
   - Khi tính tổng thể máy, crash không có dump có trọng số thấp hơn (hệ số 0.5).
8. **Giao diện PySide6 Hiện Đại (Phase 5 — Đã chốt layout 2 màn hình mẫu):**
   - Tab **Tổng quan:** 4 card thống kê, bảng crash có nhãn màu chữ (dòng nào `log_only` có nhãn "Không có dump").
   - Tab **Kết luận:** Xếp hạng nghi ngờ (% và thanh tiến độ), Bằng chứng (Dump / Log / Cập nhật), Các bước kiểm tra từ dễ đến khó, nút xuất báo cáo.
   - Mục **Khả năng ghi dump:** Bảng kiểm tra registry CrashControl và nút bật ghi dump an toàn.
9. **Đóng gói PyInstaller (Phase 6 — Cập nhật từ UPDATE_01):**
   - Đóng gói dạng thư mục (`--onedir`), không dùng `--onefile`.
   - Thư mục `config/` đặt bên cạnh file `.exe`.
   - Cấu hình `--uac-admin` để tự yêu cầu quyền Administrator.
   - Không đính kèm `cdb.exe`.

---

## 3. Kiến trúc Luồng Dữ liệu Tổng thể

```
[File Dump *.dmp] ──(dump_finder)──> [Copy an toàn & Hash SHA256]
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         [cdb_runner + cdb_parser]                         [header_parser (fallback)]
         (Chạy !analyze -v có timeout)                     (Đọc trực tiếp nhị phân)
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              ▼
                                 [SQLite DB: crash, machine]
                                 (Lưu metadata + cdb_raw_output)
                                              ▲
                                              │ (analyzed_by = 'log_only' khi không có dump)
[Windows Event Log] ──(eventlog)─────────────┼──(correlator: cửa sổ 10 phút, UTC)
(Event 41 hex, 1001, WHEA, Disk, GPU...)     │
[Thông tin Máy/Disk] ──(hardware)────────────┤
[Khả năng ghi dump] ──(check-dump-config)────┤
                                              ▼
                                  [SQLite DB: evidence]
                                              │
                                  [Rule Loader: YAML]
                                              ▼
                             [Rule Engine: scorer & verdict]
                     (Trọng số Bug Check + Module + Event Log + Patterns)
                     (Áp dụng bảng trần độ tin cậy UPDATE_01)
                                              │
                                  [SQLite DB: finding]
                                              │
                                   ┌──────────┴──────────┐
                                   ▼                     ▼
                             [CLI Engine]          [PySide6 GUI]
                                   │                     │
                                   └──────────┬──────────┘
                                              ▼
                                  [HTML / Excel Reports]
```

---

## 4. Lộ trình Triển khai theo Phase Cập nhật

- **Phase 0:** Khảo sát, tài liệu kiến trúc, 380 mã bug check, khung source code `src/dumpanalyzer`, CLI `--version`, lệnh `check-env`, 12 test pytest *(Đã hoàn thành - v0.1)*.
- **Phase 1:** Module `dump_finder` (copy an toàn, hash SHA256 cache), `header_parser` (đọc header nhị phân), schema SQLite `crash`, lệnh CLI `scan` *(Đã hoàn thành - v0.1.1)*.
- **Phase 1B (MỚI):** Lệnh CLI `check-dump-config` (kiểm tra khả năng ghi dump, pagefile, dung lượng, volmgr; hỗ trợ `--apply` có sao lưu và xác nhận an toàn) *(Đã hoàn thành - v0.1.2)*.
- **Phase 2:** Module `cdb_runner` (subprocess danh sách tham số, timeout 300s, đa luồng), `cdb_parser` (bóc tách stack, loại trừ module lõi Microsoft), warmup-symbols, fixture unit test từ output cdb mẫu *(Đã hoàn thành - v0.2.0)*.
- **Phase 3:** Module `eventlog` (Event 41 hex, 1001, WHEA, Disk...), `hardware` (SMART, disk, CPU), `drivers_updates`, `correlator` (ghép cửa sổ 10 phút UTC, gộp 41 và 1001, xử lý crash `log_only`) *(Đã hoàn thành - v0.3.0)*.
- **Phase 4:** Module `rule_loader` (validate YAML), `scorer` & `verdict` (thuật toán chấm điểm, trần tin cậy theo UPDATE_01, gắn cờ mâu thuẫn, next steps từ dễ đến khó) *(Đã hoàn thành - v0.4.0)*.
- **Phase 5:** Giao diện PySide6 theo layout đã duyệt (Tổng quan, Chi tiết, Kết luận, Cài đặt & Khả năng ghi dump; xử lý đa luồng Worker không đơ UI; xuất báo cáo HTML/Excel) *(Đã hoàn thành - v0.5.0)*.
- **Phase 6:** Phân tích đa dump/đa máy (`batch_analyzer.py`), dọn dẹp an toàn workspace, đóng gói PyInstaller `--onedir --uac-admin`, tài liệu `RULES_GUIDE.md` và `TESTING_WITH_NOTMYFAULT.md` *(Đã hoàn thành - v1.0.0)*.

