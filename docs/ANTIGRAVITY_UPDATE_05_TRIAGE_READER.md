# ĐỢT CẬP NHẬT 05 — BỘ ĐỌC MINIDUMP TÍCH HỢP (KHÔNG CẦN cdb) + PHÂN LOẠI MODULE + NHÓM USB

> Dán nội dung từ mục "PROMPT" vào Antigravity. Đi kèm **3 tệp tham chiếu** (đặt vào repo, ví dụ thư mục `docs/reference/`):
> 1. `triage_reader_reference.py` — mã tham chiếu đã chạy được trên dump mẫu.
> 2. `expected_triage_092326-67062-01.json` — kết quả mong đợi của dump mẫu.
> 3. (Chỉ để trên máy người dùng, **không đưa lên Git**) file dump mẫu `092326-67062-01.dmp` — xem mục 7.

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer**. Mục tiêu đợt này: phần mềm tự đọc được **minidump kiểu triage** (loại phổ biến trong `C:\Windows\Minidump`) bằng Python thuần để lấy bằng chứng ở mức driver/module **mà không cần `cdb`/WinDbg/symbol**, và dùng bằng chứng đó để kết luận đúng hướng hơn. Người dùng là kỹ thuật viên IT, **không biết lập trình**: mọi thay đổi phải có test, thông báo tiếng Việt rõ ràng và báo cáo cuối theo mẫu mục 10.

### 0. BỐI CẢNH VÀ LÝ DO

Ca thật đầu tiên: dump Bug Check **0x23 FAT_FILE_SYSTEM**. Phần mềm (chỉ dựa vào mã lỗi) đã nói "Ổ cứng/SSD/bộ điều khiển lưu trữ 75%, độ tin cậy thấp". Nguyên nhân thật: một USB (định dạng FAT) đang mở file bị hệ thống mất nhận dạng giữa chừng; xử lý bằng cách đổi sang cổng USB phía sau.

Phân tích trực tiếp file dump (đã làm bằng mã tham chiếu) cho thấy phần mềm **có thể** lấy được thêm các bằng chứng sau mà không cần `cdb`:

- Ngoại lệ gốc: `0xC0000005` (truy cập sai bộ nhớ), **đọc địa chỉ `0x218`** (con trỏ NULL cộng offset nhỏ), tại `ntoskrnl.exe+0x2D8334`.
- Các module xuất hiện trong ngăn xếp (quét địa chỉ trả về): `fastfat.SYS`, `FLTMGR.SYS`, `ntoskrnl.exe`, `bfs.sys` — đều là module Windows.
- Trong 199 module đang nạp **không có** driver lọc hệ thống tệp của bên thứ ba (diệt virus, sao lưu, mã hóa).
- Có `uaspstor.sys` đang nạp và `USBSTOR.SYS` nằm trong danh sách driver đã gỡ → có thiết bị lưu trữ USB hoạt động trong phiên chạy này.

Nếu không có bộ đọc này, khi có `cdb` phiên bản v1.0.0 còn coi `fastfat.sys` là "driver bên thứ ba đáng nghi" (lỗi cấu hình luật), và khi không có `cdb` thì chỉ còn mã lỗi.

### 1. ĐIỀU KIỆN TIÊN QUYẾT (kiểm tra trước; chưa xong thì DỪNG và báo cáo)

1. Hotfix 01 (`schema.sql`), Hotfix 02 (CLI/`selftest`), Hotfix 03 (luồng phân tích dùng `engine/pipeline.py`) đã gộp và `pytest` PASS.
2. Đợt 02 nhóm A (scorer: WHEA, `cap`, `import json`, pattern) và nhóm B (header dump) đã gộp. **Nếu nhóm B chưa làm**, hạng mục 3.2 dưới đây là bắt buộc.
3. Nếu các prompt trước về "fastfat.sys / hệ thống tệp / nhóm USB" đã làm thì mở rộng chúng; nếu chưa, các hạng mục 3.5–3.6 đã bao gồm phần cốt lõi của chúng. Không làm trùng.

### 2. NGUYÊN TẮC BẮT BUỘC

| # | Nguyên tắc | Lý do |
|---|---|---|
| N1 | **Không bao giờ ném ngoại lệ vì dữ liệu dump hỏng.** Mỗi phần đọc độc lập, lỗi → thêm cảnh báo, bỏ phần đó, các phần khác vẫn chạy | Dump có thể bị cắt/hỏng; công cụ không được sập |
| N2 | **Kiểm tra giới hạn mọi offset/kích thước/số lượng** trước khi đọc; không đọc quá 16 MB đầu file | Chống file hỏng/độc hại, chống tốn bộ nhớ |
| N3 | **Chỉ đọc đúng các phần cần thiết** (header, ngoại lệ, ngữ cảnh, danh sách module, danh sách driver đã gỡ, vùng ngăn xếp). **Không đọc, không lưu** vùng tiến trình/luồng, chuỗi dòng lệnh hay bộ nhớ khác | Quyền riêng tư: dump chứa mảnh bộ nhớ của máy |
| N4 | **Phân biệt "đã kiểm chứng" và "chưa kiểm chứng".** Cấu trúc ở mục 3.1 mới được kiểm chứng trên **một** dump (Windows 11 build 26100). Mọi chỗ khác phải đánh dấu `[CẦN XÁC MINH]` | Tránh khẳng định quá mức |
| N5 | **Quét ngăn xếp chỉ là ứng viên (heuristic), không phải backtrace chuẩn.** Bằng chứng từ nó tối đa mức *vừa*, không bao giờ *mạnh* | Ngăn xếp còn dữ liệu cũ; không có symbol |
| N6 | **Không nêu tên một driver là thủ phạm chỉ vì tên nó có trong module hoặc ngăn xếp.** Chỉ module thuộc danh sách "bên thứ ba đã biết" (cấu hình được) hoặc được `cdb`/`lmvm` xác nhận không phải Microsoft mới được nêu tên | Tên module không chứng minh nhà sản xuất |
| N7 | **Không chỉnh luật theo đúng một ca.** Trọng số ban đầu ở mục 3.6 là *khởi điểm tạm*, ghi rõ cần hiệu chỉnh khi có thêm ca | n = 1 |
| N8 | `cdb` (nếu có và chạy tốt) **vẫn ưu tiên** cho tên module/stack; bộ đọc nội bộ là phương án dự phòng và là bản đối chiếu chéo | `cdb` có symbol nên chính xác hơn |
| N9 | Tương thích ngược: CSDL, YAML, CLI hiện có không được vỡ. Khóa/cột mới thiếu → mặc định | Dữ liệu và luật cũ của người dùng |
| N10 | Không bịa. Điều gì không kiểm chứng được ở môi trường của bạn phải ghi "chưa kiểm chứng" kèm cách người dùng tự kiểm tra | Người dùng sẽ tin vào kết quả |

### 3. ĐẶC TẢ

#### 3.1. Cấu trúc minidump triage đã giải mã (offset TUYỆT ĐỐI từ đầu file, little-endian)

Tệp tham chiếu `triage_reader_reference.py` hiện thực đúng bảng này. **Cột "Kiểm chứng": ✅ = khớp trên dump mẫu; ⚠️ = suy luận/chưa kiểm chứng.**

| Vùng | Offset | Kiểu | Ý nghĩa | Kiểm chứng |
|---|---|---|---|---|
| Header | `0x00` / `0x04` | 4 byte ×2 | `PAGE` / `DU64` | ✅ |
| | `0x08`, `0x0C` | u32 | Phiên bản chính, **số build** (26100) | ✅ |
| | `0x30`, `0x34` | u32 | Kiến trúc (`0x8664`), số CPU logic | ✅ |
| | `0x38` | u32 | Mã Bug Check | ✅ |
| | `0x40..0x58` | 4×u64 | Tham số 1..4 | ✅ |
| | `0xF98` | u32 | **Loại dump** (1 full, 2 kernel, 3 header, **4 triage**) | ✅ (giá trị 4) |
| | `0xFA8` | u64 | **Giờ dump** (FILETIME, UTC) | ✅ (khớp tên file `092326` = 23/09/2026) |
| | `0xFB0` | 128 byte | Comment (dump mẫu chỉ có `PAGE` lặp lại) | ✅ (không dùng) |
| | `0xFF8` | u64 | SystemUpTime | ❌ **giá trị rác trên dump mẫu — KHÔNG dùng** |
| | `0xA0` | | Offset mà v1.0.0 đang dùng làm giờ sập | ❌ **sai** (đọc ra 94) |
| Triage | `0x2000` | 18×u32 | `ServicePackBuild, SizeOfDump, ValidOffset, ContextOffset, ExceptionOffset, MmOffset, UnloadedDriversOffset, PrcbOffset, ProcessOffset, ThreadOffset, CallStackOffset, SizeOfCallStack, DriverListOffset, DriverCount, StringPoolOffset, StringPoolSize, BrokenDriverOffset, TriageOptions` — tất cả là offset **tuyệt đối từ đầu file** | ✅ |
| | `0x2048` | u64 | `TopOfStack`: địa chỉ ảo của byte đầu vùng call stack | ✅ |
| | `ValidOffset` | 4 byte | Dấu hiệu hợp lệ `TRGD`, nằm ngay trước `SizeOfDump` (vùng triage = `[0x2000, SizeOfDump)`) | ✅ |
| Call stack | `CallStackOffset`, dài `SizeOfCallStack` | byte | Bộ nhớ ngăn xếp. Ánh xạ: `offset_file = CallStackOffset + (địa_chỉ_ảo − TopOfStack)` | ✅ (tham số 2 và 3 của 0x23 đều rơi vào vùng này và cho dữ liệu hợp lý) |
| Ngoại lệ | tại tham số 2 của Bug Check 0x23 (trong vùng call stack) | `EXCEPTION_RECORD64` | `+0x00` mã (u32), `+0x04` cờ, `+0x10` địa chỉ ngoại lệ (u64), `+0x18` số tham số (u32), `+0x20` các tham số (u64). Với `0xC0000005`: tham số 0 = loại truy cập (0 đọc, 1 ghi, 8 thực thi), tham số 1 = địa chỉ bị truy cập | ✅ |
| Ngữ cảnh | tại tham số 3 của 0x23 | `CONTEXT` x64 | `+0x98` RSP, `+0xF8` RIP | ✅ (RIP = địa chỉ ngoại lệ = tham số 4) |
| Danh sách module | `DriverListOffset`, `DriverCount` mục, **mỗi mục 144 byte (0x90)** | | `+0x00` u64 = offset tuyệt đối tới bản ghi tên trong string pool; `+0x38` u64 `DllBase`; `+0x48` u32 `SizeOfImage` | ✅ (199 module đọc được) |
| String pool | `StringPoolOffset`, `StringPoolSize` | | Bản ghi tên: `u32 số ký tự` + UTF-16LE + NUL, căn 4 byte | ✅ |
| Driver đã gỡ | `UnloadedDriversOffset` | | `u32 số lượng` (+4 byte đệm), rồi mỗi mục **0x38 byte**: tên UTF-16 (**tối đa 12 ký tự**) tại `+0x10`. Khớp: `UnloadedDriversOffset + 8 + số_lượng×0x38 = DriverListOffset` | ✅ về tên và độ dài; ⚠️ chưa giải mã địa chỉ đầu/cuối và **không có mốc thời gian** |
| Các trường khác trong mục module (`+0x78`, `+0x80`...) | | | Chưa xác định ý nghĩa | ⚠️ không dùng |

Ghi nhớ: **kết quả mong đợi cho dump mẫu** nằm trong `expected_triage_092326-67062-01.json` (OS build 26100, loại dump triage, giờ `2026-09-23T10:59:30Z`, Bug Check `0x23`, tham số 1 `0xE0121`, ngoại lệ `0xC0000005` đọc `0x218`, module `ntoskrnl.exe+0x2D8334`, 199 module, 50 driver đã gỡ gồm `USBSTOR.SYS`, thứ tự module trong stack `ntoskrnl.exe → fastfat.SYS → FLTMGR.SYS → bfs.sys`).

**Phạm vi:** chỉ dump `PAGEDU64` có `DumpType == 4`. Dump kernel/complete (loại 1, 2, 3) → chỉ đọc header (đã đủ để lấy mã lỗi, loại dump, giờ) và dùng `cdb`. Dump 32-bit (`PAGEDUMP`) hoặc minidump người dùng (`MDMP`) → cảnh báo "không hỗ trợ", không lỗi.

#### 3.2. Sửa đọc header (`analyzer/header_parser.py`) — nếu Đợt 02 nhóm B chưa làm

- `SystemTime` đọc tại **`0xFA8`** (FILETIME), không phải `0xA0`; hợp lệ khi năm nằm trong 2000–2100, ngược lại rơi về giờ sửa file.
- Đọc `DumpType` tại **`0xF98`** để điền `dump_type` (`full|kernel|header|triage`) thay vì luôn là `kernel`.
- **Không** dùng `SystemUpTime` tại `0xFF8`.
- Thêm cột `crash_time_source` (`header` | `mtime`) vào bảng `crash` (migration) và hiển thị trong giao diện/báo cáo.
- Test với dump mẫu (mục 7) và với tệp tổng hợp.

#### 3.3. Module mới `src/dumpanalyzer/analyzer/triage_reader.py`

Chuyển mã tham chiếu thành mã sản xuất, giữ **cùng kết quả** trên dump mẫu:

```python
@dataclass
class TriageResult:
    ok: bool
    warnings: list[str]
    header: dict          # os_build, dump_type, system_time_utc, bugcheck_code, params...
    exception: dict       # code, address, module, module_offset, parameters, meaning
    context: dict         # rip, rsp, rip_module...
    modules: list[dict]   # name, base, size
    unloaded: list[str]
    stack_candidates: list[dict]       # tối đa N phần tử (cấu hình, mặc định 200)
    stack_modules_in_order: list[str]

def read_triage(path: str | Path, *, max_bytes: int = 16 << 20) -> TriageResult: ...
```

Yêu cầu:
- Tuân thủ N1–N5. Mọi truy cập dùng hàm có kiểm tra giới hạn; số lượng driver ≤ 2000, string pool ≤ 1 MB, số driver đã gỡ ≤ 256.
- Chỉ đọc phần đầu file (tối đa `max_bytes`); không nạp cả file dump lớn vào bộ nhớ.
- Giữ nguyên ngữ nghĩa các cảnh báo của mã tham chiếu (ví dụ dấu hiệu `TRGD` không khớp, tham số 2/3 ngoài vùng call stack).
- Chỉ áp dụng cho Bug Check có ngoại lệ ở tham số 2/3 theo quy ước đã kiểm chứng (0x23 trên dump mẫu). Với **Bug Check khác**, vẫn đọc danh sách module/driver đã gỡ và quét stack từ đầu vùng call stack, nhưng **không** diễn giải tham số 2/3 là ngoại lệ/ngữ cảnh (đánh dấu `[CẦN XÁC MINH]` cho từng mã khi mở rộng; danh sách mã hỗ trợ ngoại lệ nằm trong YAML `triage_reader.exception_bugchecks`, mặc định `["0x23", "0x24"]`).
- Ghi log mức `DEBUG` có tên phần bị bỏ qua và lý do (không ghi nội dung bộ nhớ).

#### 3.4. Tích hợp vào luồng phân tích (`analyzer/cdb_runner.py`, `engine/pipeline.py`)

Thứ tự trong `build_crash_from_dump` (hoặc hàm tương đương):

1. Đọc header (3.2) → `dump_type`, `crash_time_utc`, `crash_time_source`, mã lỗi, tham số.
2. Nếu `dump_type == "triage"` và `settings.triage_reader.enabled` → `read_triage` (3.3).
3. Nếu có `cdb` và chạy thành công → `analyzed_by = "cdb"`, dùng kết quả `cdb` cho tên module; **vẫn lưu** kết quả triage để đối chiếu chéo và ghi cảnh báo nếu lệch (ví dụ khác địa chỉ ngoại lệ hoặc khác module).
4. Nếu không có `cdb` nhưng triage đọc được → `analyzed_by = "triage_native"` (**giá trị mới**, khác `header_only`), điền các trường `crash` có sẵn (`image_name`/`module_name` **không** lấy từ ngoại lệ nếu module đó là module Microsoft lõi như `ntoskrnl.exe`; xem 3.5).
5. Ngược lại → `header_only` như cũ.

Lưu trữ (migration tương thích ngược trong `storage/db.py`, và cập nhật `schema.sql`):
- Cột mới trong `crash`: `exception_code TEXT`, `exception_address TEXT`, `exception_module TEXT`, `triage_json TEXT` (toàn bộ `TriageResult` đã rút gọn: không quá 300 module, không quá 200 ứng viên stack, **không** có dữ liệu bộ nhớ thô), `crash_time_source TEXT`. Các cột `p1..p4` hiện có tiếp tục dùng cho tham số Bug Check.
- Giới hạn kích thước `triage_json` (ví dụ 256 KB), vượt thì cắt phần module và ghi chú.

Các bước dùng chung cho CLI và GUI qua `engine/pipeline.py` (Hotfix 03); không viết lại logic ở worker.

#### 3.5. Phân loại module (`config/rules/module_classes.yaml` — tệp mới)

Cho phép phân loại tên module vào các lớp, **không khẳng định nhà sản xuất** (N6):

```yaml
version: 1
classes:
  ms_inbox:            # module Windows thường gặp; KHÔNG bao giờ bị coi là thủ phạm bên thứ ba
    - ntoskrnl.exe
    - hal.dll
    - fastfat.sys
    - exfat.sys
    - ntfs.sys
    - refs.sys
    - udfs.sys
    - cdfs.sys
    - fltmgr.sys
    - bfs.sys              # [CẦN XÁC MINH] theo hiểu biết hiện tại là Brokering File System của Microsoft
    - luafv.sys
    - wof.sys
    - bindflt.sys
    - cldflt.sys
    - fileinfo.sys
    - disk.sys
    - classpnp.sys
    - partmgr.sys
    - volmgr.sys
    - volmgrx.sys
    - volsnap.sys
    - storport.sys
    - ataport.sys
    - usbxhci.sys
    - usbhub3.sys
    - ucx01000.sys
    - usbd.sys
    - usbccgp.sys
    - usbstor.sys
    - uaspstor.sys
    - wdfilter.sys
    - wdnisdrv.sys
  fs_stack:            # nằm trên đường xử lý tệp (chỉ là chỉ báo đường đi, không phải nghi phạm)
    - fastfat.sys
    - exfat.sys
    - ntfs.sys
    - refs.sys
    - fltmgr.sys
    - bfs.sys
    - luafv.sys
    - wof.sys
    - bindflt.sys
    - cldflt.sys
    - fileinfo.sys
  usb_storage_driver:  # CHỈ driver lớp lưu trữ USB mới là chỉ báo có thiết bị lưu trữ USB
    - usbstor.sys
    - uaspstor.sys
  third_party_filter_known:   # ví dụ khởi điểm, người dùng bổ sung/chỉnh; [CẦN XÁC MINH] từng tên
    - klif.sys
    - mfehidk.sys
    - mfeavfk.sys
    - epfwwfp.sys
    - eamonm.sys
    - avgntflt.sys
    - aswsp.sys
    - aswsnx.sys
    - bdfsfltr.sys
    - symevnt.sys
    - csagent.sys
    - sentinelmonitor.sys
    - tmactmon.sys
```

Quy tắc áp dụng:
- So khớp **không phân biệt hoa thường**, so theo tên đầy đủ (`fastfat.SYS` ≡ `fastfat.sys`). Tên bị cắt ở 12 ký tự trong danh sách driver đã gỡ phải so khớp theo tiền tố (ví dụ `USBSTOR.SYS` vừa đủ 11 ký tự; `hiber_stornv` là tên đã cắt).
- **`usbxhci.sys`, `usbhub3.sys`, `ucx01000.sys`, `usbd.sys`, `usbccgp.sys` có mặt hầu như trên mọi máy hiện đại**, nên **không** được dùng làm bằng chứng cho nhóm USB. Chỉ `usb_storage_driver` (`usbstor.sys`, `uaspstor.sys`) mới là chỉ báo thiết bị lưu trữ USB đã hoạt động. Có test riêng cho điểm này.
- Module **không thuộc lớp nào** là "chưa phân loại": hiển thị trong báo cáo, **không** bị coi là thủ phạm (N6).
- Thay thế cách dùng `ms_core_modules` trong `driver_map.yaml` bằng `ms_inbox` mới nhưng **vẫn đọc** `ms_core_modules` cũ để tương thích (gộp hai danh sách).
- Nếu `cdb` có và `lmvm` trả về nhà sản xuất, ưu tiên thông tin đó để quyết định "Microsoft/không" (Đợt sau); đợt này chỉ cần giữ chỗ trong mã (hàm phân loại nhận thêm tham số tùy chọn).

#### 3.6. Luật bằng chứng từ dump (`config/rules/triage_rules.yaml` — tệp mới)

Nhóm nghi ngờ mới `usb_peripheral` (nhãn hiển thị: "Thiết bị USB / cổng USB / nguồn USB"). Nếu đã thêm ở prompt trước thì dùng lại; nếu chưa thì thêm vào scorer, `rule_loader`, giao diện, báo cáo, `validate-rules`, bảng đối chiếu.

Bằng chứng sinh ra có `kind = "dump"` (hoặc tên đã dùng sẵn), kèm `rule_id`, `strength` (`weak|medium`), và hiển thị trong báo cáo. Scorer **chỉ thêm** nhánh xử lý bằng chứng `dump` theo bảng luật; **không đổi** logic chấm điểm hiện có ngoài việc đó và phải dùng chung hàm tính điểm đã tách ở Đợt 02 (nhóm A1). Ví dụ khởi điểm:

```yaml
version: 1
fs_bugchecks: ["0x23", "0x24"]      # [CẦN XÁC MINH] có nên thêm 0x12C (exFAT) không
rules:
  - id: fs_path_all_microsoft
    when:
      bugcheck_in: fs_bugchecks
      stack_has_class: fs_stack
      stack_has_class_not: third_party_filter_known
    effect: { reduce: { driver: 15 }, add: { storage: 5 } }   # reduce = trừ điểm, sàn 0 (nếu Đợt 03 đã có polarity thì dùng refute)
    strength: medium
    summary: "Đường xử lý lỗi chỉ gồm module Microsoft; không thấy driver lọc bên thứ ba trong ngăn xếp"
  - id: usb_mass_storage_active
    when:
      bugcheck_in: fs_bugchecks
      modules_have_class: usb_storage_driver
    effect: { add: { usb_peripheral: 15 } }
    strength: weak
    summary: "Có driver lưu trữ USB đang nạp: thiết bị lưu trữ USB đã hoạt động trong phiên chạy này"
  - id: usb_mass_storage_churn
    when:
      bugcheck_in: fs_bugchecks
      unloaded_has_class: usb_storage_driver
    effect: { add: { usb_peripheral: 10 } }
    strength: weak
    summary: "Driver lưu trữ USB từng được nạp rồi gỡ trong phiên chạy này"
  - id: third_party_filter_in_stack
    when:
      stack_has_class: third_party_filter_known
    effect: { add: { driver: 30 } }
    strength: medium
    summary: "Driver lọc bên thứ ba xuất hiện trong ngăn xếp (ứng viên, cần xác nhận)"
  - id: null_dereference_info
    when:
      exception_code: "0xC0000005"
      exception_access: read
      exception_address_lt: 0x10000
    effect: {}                        # chỉ hiển thị, không cộng điểm
    strength: info
    summary: "Truy cập con trỏ NULL (đọc địa chỉ nhỏ): thường là đối tượng đã bị giải phóng/mất"
```

Quy tắc kèm theo:
- Điều kiện `stack_has_class`, `stack_has_class_not`, `modules_have_class`, `unloaded_has_class` đọc từ `TriageResult`. Điều kiện không thể đánh giá (thiếu dữ liệu) → luật **không kích hoạt** (không phải lỗi).
- Cập nhật `bugcheck_rules.yaml` cho `0x23`, trọng số ban đầu (**khởi điểm tạm, không tối ưu theo một ca, N7**): `storage: 50, usb_peripheral: 25, driver: 15, ram: 10`. Viết lại `next_steps` theo ca thật: rút thiết bị USB ra, thử cổng khác (ưu tiên cổng phía sau gắn trực tiếp bo mạch), tránh hub không nguồn, thử cáp khác, thử thiết bị trên máy khác, kiểm tra thiết bị bằng `chkdsk` (chỉ chạy `/f` sau khi sao lưu), xem sự kiện USB/Disk quanh giờ sập. **Giao diện và báo cáo phải hiển thị `next_steps`.**
- Nhãn nhóm `storage` đổi thành "Hệ thống tệp / ổ lưu trữ (kể cả USB, thẻ nhớ)".
- Độ tin cậy: bằng chứng `dump` từ bộ đọc nội bộ tối đa *vừa* (N5); khi không có Event Log, kết luận vẫn ở mức thấp/trung bình theo chính sách hiện hành; không nới trần.

#### 3.7. Hiển thị (GUI, CLI, báo cáo HTML/Excel)

Thêm khối **"Bằng chứng từ dump"** trong Tab chi tiết và báo cáo, chỉ hiện khi có dữ liệu triage:
- Ngoại lệ: mã, ý nghĩa (ví dụ "Truy cập sai bộ nhớ: đọc địa chỉ 0x218 (con trỏ NULL + offset nhỏ)"), module và offset nơi xảy ra (ghi chú "chưa có symbol nên chưa biết tên hàm").
- Module trong ngăn xếp **theo thứ tự**, kèm nhãn "ứng viên (quét heuristic, không phải backtrace chuẩn)", tô nổi bật module thuộc `fs_stack`, `third_party_filter_known` và "chưa phân loại".
- Module liên quan lưu trữ/USB đang nạp, driver đã gỡ có liên quan (ví dụ `USBSTOR.SYS`).
- Tham số 1 của Bug Check (ví dụ `0xE0121`) kèm ghi chú: "dùng để gom các ca cùng điểm lỗi; ý nghĩa chi tiết chưa đối chiếu với tài liệu chính thức".
- Nguồn dữ liệu: nhãn `analyzed_by` hiển thị tiếng Việt ("Phân tích nội bộ (không cần cdb)" cho `triage_native`), `crash_time_source`, và các cảnh báo của bộ đọc.

#### 3.8. Lệnh CLI mới (phục vụ kiểm chứng trên nhiều dump)

| Lệnh | Chức năng |
|---|---|
| `triage-info <file.dmp> [--json]` | In kết quả bộ đọc nội bộ (giống mã tham chiếu). JSON **không** chứa dữ liệu bộ nhớ, tên người dùng hay tên máy |
| `triage-compare <file.dmp>` | Nếu có `cdb`: chạy cả hai và in đối chiếu cạnh nhau (mã lỗi, địa chỉ ngoại lệ, module); ghi cảnh báo nếu lệch |

Mục đích: người dùng chạy `triage-info --json` trên nhiều dump (các máy, các phiên bản Windows khác nhau) và gửi kết quả JSON nhỏ để xác minh cấu trúc ở mục 3.1 (N4).

#### 3.9. Cấu hình (`config/settings.yaml`, thiếu thì dùng mặc định)

```yaml
triage_reader:
  enabled: true
  max_bytes: 16777216
  max_modules: 300
  max_stack_candidates: 200
  exception_bugchecks: ["0x23", "0x24"]
```

Thêm vào `validate-rules` các tệp `module_classes.yaml` và `triage_rules.yaml`; ghi tài liệu trong `docs/RULES_GUIDE.md`.

### 4. VIỆC KHÔNG LÀM TRONG ĐỢT NÀY

- Không phân giải symbol, không đoán tên hàm, không disassembly.
- Không đọc dump kernel/complete (chỉ header + `cdb`), không hỗ trợ dump 32-bit, không hỗ trợ minidump người dùng (`MDMP`).
- Không đọc vùng tiến trình/luồng/dòng lệnh; không lưu dữ liệu bộ nhớ thô.
- Không đổi luật chấm điểm ngoài phần nêu ở 3.6; không tối ưu trọng số theo một ca.
- Không đụng các phần Event Log (đã có prompt riêng); không đổi đóng gói ngoài việc bảo đảm các tệp YAML mới nằm trong gói.

### 5. TEST BẮT BUỘC

**5.1. Dữ liệu tổng hợp (CI)** — tạo trình sinh tệp tổng hợp `src/dumpanalyzer/analyzer/_selftest_fixture.py` (trong gói, để `selftest` dùng được cả khi đã đóng gói) với hàm `build_synthetic_triage(modules, unloaded, exception, stack_modules, bugcheck="0x23", ...) -> bytes` dựng đúng bố cục ở 3.1 (header `PAGEDU64`, `DumpType=4`, `SystemTime` tại `0xFA8`, cấu trúc triage tại `0x2000`, danh sách module 144 byte/mục, string pool, danh sách driver đã gỡ 0x38 byte/mục, vùng call stack chứa `EXCEPTION_RECORD64` và `CONTEXT` ở các địa chỉ trỏ bởi tham số 2 và 3, dấu `TRGD`).

**5.2. Dump thật (chỉ chạy khi có file, xem mục 7):** `tests/test_triage_real_sample.py` kiểm tra đúng các giá trị trong `expected_triage_092326-67062-01.json`:
- OS build 26100; loại dump `triage`; giờ `2026-09-23T10:59:30Z`; Bug Check `0x23`; tham số `["0xE0121", "0xFFFFBB8A25D467C8", "0xFFFFBB8A25D45FB0", "0xFFFFF80585ED8334"]`;
- ngoại lệ `0xC0000005`, tham số `["0x0", "0x218"]`, địa chỉ `0xFFFFF80585ED8334`, module `ntoskrnl.exe`, offset `0x2D8334`;
- 199 module, 50 mục driver đã gỡ trong đó có `USBSTOR.SYS`;
- thứ tự module trong stack bắt đầu `ntoskrnl.exe, fastfat.SYS, FLTMGR.SYS, bfs.sys` (**không** khẳng định số lần xuất hiện chính xác vì đó là heuristic);
- không có module thuộc `third_party_filter_known`; có `uaspstor.sys` trong danh sách đang nạp.
- Test tự **bỏ qua** (`skip`) nếu file không có, và **không bao giờ** đọc file từ vị trí nằm trong Git.

**5.3. Bền vững/độ chịu lỗi** (dùng dữ liệu tổng hợp): file rỗng; chỉ có header; cắt ngắn ở nhiều vị trí; sai chữ ký; `PAGEDUMP` (32-bit); `DumpType` khác 4; `DriverCount` cực lớn hoặc offset ngoài file; string pool hỏng; tên module có ký tự không ASCII; `SizeOfDump` bất thường; dấu `TRGD` sai. Mọi trường hợp trả `TriageResult` với cảnh báo, **không ném ngoại lệ**, và không tốn bộ nhớ quá giới hạn.

**5.4. Phân loại module:** so khớp không phân biệt hoa thường; tên driver đã gỡ bị cắt 12 ký tự; **dump chỉ có `usbxhci/usbhub3/usbccgp` (không có `usbstor/uaspstor`) không được tăng điểm `usb_peripheral`**; module chưa phân loại không bị coi là thủ phạm; `fastfat.sys` không tạo nghi phạm `driver:fastfat.sys`.

**5.5. Luật và chấm điểm (so sánh tương đối, không so số tuyệt đối):**
- Ca mẫu (0x23, stack toàn module Microsoft, có `uaspstor` và `USBSTOR` đã gỡ, không có Event Log): không có nghi phạm `driver:fastfat.sys`; `usb_peripheral` nằm trong **top 2**; điểm `driver` (bên thứ ba) thấp hơn trước khi có bộ đọc; độ tin cậy **không** vượt mức trần hiện hành.
- Thêm một driver lọc thuộc `third_party_filter_known` vào ngăn xếp tổng hợp → xuất hiện nghi phạm driver có tên, mức *vừa*.
- Bug Check khác nhóm hệ tệp (ví dụ `0xD1`) → các luật nhóm hệ thống tệp không kích hoạt.
- Không có dữ liệu triage (header_only) → kết quả như trước khi có đợt này (hồi quy).

**5.6. Tích hợp:** chạy pipeline (Hotfix 03) với tệp tổng hợp và với dump mẫu (nếu có): `crash` có cột mới đúng; `analyzed_by = "triage_native"` khi không có `cdb`; giao diện offscreen hiển thị khối "Bằng chứng từ dump"; báo cáo xuất được; migration từ CSDL v1.0.0 không mất dữ liệu.

**5.7. `selftest` (Hotfix 02):** thêm mục kiểm tra bộ đọc triage bằng tệp tổng hợp trong bộ nhớ (chạy được trong bản `.exe`), và kiểm tra `module_classes.yaml`, `triage_rules.yaml` hợp lệ.

`python -m ruff check src` và `python -m pytest -q` phải PASS; workflow GitHub xanh.

### 6. TIÊU CHÍ HOÀN THÀNH

1. Với dump mẫu: `triage-info` in ra đúng các giá trị ở 5.2; phân tích bằng GUI/CLI cho kết luận có khối "Bằng chứng từ dump" và không còn nhắc `fastfat.sys` như driver bên thứ ba.
2. Mọi tệp dump hỏng/cắt cụt không làm sập chương trình.
3. Không có đường nào đọc/lưu dữ liệu ngoài danh sách ở N3.
4. `analyzed_by = "triage_native"` được dùng đúng; `crash_time_source` hiển thị đúng.

### 7. DUMP MẪU VÀ QUYỀN RIÊNG TƯ

- Dump mẫu `092326-67062-01.dmp` chứa các mảnh bộ nhớ của máy thật. **Không** đưa vào Git/GitHub/artifact. Người dùng đặt cục bộ tại `tests/private_fixtures/092326-67062-01.dmp`; thêm `tests/private_fixtures/` vào `.gitignore`; test tương ứng tự bỏ qua nếu thiếu.
- `expected_triage_092326-67062-01.json` chỉ chứa tên module, địa chỉ và giá trị Bug Check (không có dữ liệu người dùng) nên có thể đưa vào `tests/fixtures/` để dùng làm giá trị mong đợi.
- Mã tham chiếu `triage_reader_reference.py` đặt ở `docs/reference/` và **không** được `import` bởi mã sản xuất.

### 8. RỦI RO VÀ BIỆN PHÁP

| Rủi ro | Biện pháp |
|---|---|
| Bố cục khác ở phiên bản Windows khác | N4; kiểm tra giới hạn; cảnh báo thay vì lỗi; lệnh `triage-info --json` để thu mẫu; `triage-compare` đối chiếu với `cdb` |
| Kết luận quá tự tin từ quét stack | N5, N6; tối đa mức *vừa*; nhãn "ứng viên" trong giao diện |
| Chấm sai vì tên module trùng/không rõ nhà sản xuất | Lớp "chưa phân loại" không bị đổ lỗi; danh sách bên thứ ba do người dùng chỉnh |
| Tối ưu theo một ca | N7; trọng số khởi điểm tạm; thu thêm ca qua bảng đối chiếu và nút đúng/sai (Đợt 03) |
| Rò rỉ dữ liệu | N3; `triage_json` không có dữ liệu bộ nhớ; dump mẫu không đưa lên Git |
| Dump lớn làm chậm/đầy bộ nhớ | N2; chỉ đọc 16 MB đầu |

### 9. THỨ TỰ THỰC HIỆN

Nhánh `feature/update-05-triage-reader`, mỗi bước một commit; sau mỗi bước chạy `ruff` và `pytest`:
1. Header (3.2, nếu chưa có) + bộ sinh dữ liệu tổng hợp (5.1).
2. `triage_reader.py` + test độ chịu lỗi (3.3, 5.3) + test dump thật (5.2).
3. `module_classes.yaml` + phân loại (3.5, 5.4).
4. Lưu trữ + tích hợp luồng phân tích (3.4, 5.6).
5. `triage_rules.yaml` + nhóm `usb_peripheral` + chỉnh `bugcheck_rules.yaml` (3.6, 5.5).
6. Giao diện/báo cáo/CLI (3.7, 3.8), `selftest` (5.7), tài liệu, CHANGELOG, tăng phiên bản.

### 10. BÁO CÁO CUỐI (tiếng Việt)

1. Đã làm gì (file, hàm, cột, khóa YAML mới/đổi).
2. Test đã thêm, kết quả `pytest`/`ruff`/workflow, và xác nhận kết quả dump mẫu khớp `expected_triage_...json`.
3. Danh sách `[CẦN XÁC MINH]` và việc cần người dùng kiểm tra (đặc biệt: chạy `triage-info --json` trên ít nhất 10 dump khác nhau).
4. Quyết định đã đưa ra, việc bỏ dở và lý do.
5. Danh sách commit, phiên bản/tag.

---

## PHỤ LỤC — Việc người dùng tự làm sau khi Antigravity xong

1. Đặt file dump mẫu vào `tests/private_fixtures/` (không đưa lên Git) rồi chạy bộ test để xác nhận khớp.
2. Chạy lệnh dưới đây trên **ít nhất 10 dump** từ nhiều máy/phiên bản Windows, rồi gửi lại các tệp JSON (nhỏ, không chứa dữ liệu bộ nhớ) để xác minh cấu trúc:

```bash
DumpAnalyzer-cli.exe triage-info "C:\Windows\Minidump\TÊN_FILE.dmp" --json > ketqua_triage.json
```

3. Nếu máy có `cdb`, chạy `DumpAnalyzer-cli.exe triage-compare "<file>"` và gửi kết quả nếu có điểm lệch.
4. Ghi các ca mới vào bảng đối chiếu (nhớ cột "đúng một phần" và nhóm "Thiết bị USB/ngoại vi").
