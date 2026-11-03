# ĐỢT CẬP NHẬT 04 — MÁY KHÔNG GHI DUMP: PHÁT HIỆN, BẬT AN TOÀN, THEO DÕI ĐỘI MÁY, PHÂN TÍCH KHI THIẾU DUMP

> Tài liệu bàn giao cho Antigravity. Dán toàn bộ nội dung từ mục "PROMPT" vào Antigravity (hoặc đưa cả file vào repo, ví dụ `docs/handoff/UPDATE_04.md`).
> Tài liệu có **phần lý luận** (mục 1–3) để Antigravity hiểu *vì sao* làm vậy, rồi mới đến **đặc tả triển khai** (mục 4–10). Khi gặp tình huống không được mô tả, hãy quay lại các nguyên tắc ở mục 2 để quyết định, không tự suy diễn.

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer** (Python, PySide6, SQLite, YAML rules; đóng gói PyInstaller onedir). Người dùng là kỹ thuật viên IT, **không biết lập trình**, nên mọi thay đổi phải có test, có thông báo tiếng Việt rõ ràng, và có báo cáo cuối theo mẫu ở mục 12.

### 0. TÓM TẮT ĐIỀU HÀNH

**Vấn đề:** nhiều máy không ghi file dump khi BSOD (đã tắt ghi dump, thiếu pagefile, đầy ổ đĩa, dump bị dọn dẹp...). Với các máy đó phần mềm chỉ chạy được chế độ `log_only`, độ chính xác thấp và không nêu được driver nghi vấn.

**Giải pháp gồm 5 phần:**

| Phần | Nội dung | Kết quả cho người dùng |
|---|---|---|
| A | Củng cố bộ kiểm tra "sẵn sàng ghi dump" (mô hình trạng thái, mã lý do, sửa các lỗ hổng đã tìm thấy) | Biết chính xác máy nào, vì sao không ghi được dump |
| B | Hành động **bật ghi dump** an toàn (sao lưu đầy đủ, hoàn tác, nhật ký, không tự khởi động lại) | Nút "Bật ghi dump" cho máy cục bộ |
| C | Giao diện và CLI | Tab "Sẵn sàng ghi dump", lệnh `dump-readiness`, `dump-enable`, `dump-rollback` |
| D | **Đội máy**: thu trạng thái từ nhiều máy, bật hàng loạt qua gói triển khai hoặc từ xa (tùy chọn) | Bảng tổng quan đội máy + nút bật cho các máy đã chọn |
| E | Phân tích khi không có dump (`log_only`) chặt chẽ hơn + phát hiện "dump bị mất" | Kết luận đúng mức tin cậy, kèm khuyến nghị bật dump |

**Điều kiện tiên quyết** (kiểm tra trước, nếu chưa xong thì DỪNG và báo cáo):
1. Hotfix 01 (`schema.sql` trong gói đóng gói) đã gộp.
2. Hotfix 02 (CLI đóng gói, `selftest`) đã gộp.
3. Đợt 02 đã gộp, đặc biệt nhóm C (đọc Event Log bằng PowerShell), nhóm D (giờ sập của ca `log_only`) và nhóm E (Event 1001 không phụ thuộc ngôn ngữ). Đợt này **dựa vào** chúng.
Đợt 03 không phải điều kiện tiên quyết; nếu Đợt 03 đã gộp thì dùng chung cơ chế migration CSDL, nếu chưa thì tự thêm migration tương thích ngược theo cùng kiểu trong `storage/db.py`.

---

## 1. BỐI CẢNH VÀ PHÂN TÍCH VẤN ĐỀ (LÝ LUẬN)

### 1.1. Vì sao một máy không có file dump

Không nên gộp mọi nguyên nhân thành "chưa bật". Có ít nhất 6 nhóm nguyên nhân khác nhau, mỗi nhóm cần cách xử lý khác nhau:

| # | Nguyên nhân | Dấu hiệu nhận biết | Cách xử lý đúng |
|---|---|---|---|
| 1 | Cấu hình tắt: `CrashDumpEnabled = 0` | Đọc trực tiếp registry | Bật (nút "Bật ghi dump") |
| 2 | Không có (hoặc không đọc được) giá trị registry | `CrashDumpEnabled` không tồn tại, hoặc lỗi đọc | Phân biệt "không tồn tại" với "không đọc được". Chỉ ghi giá trị khi chắc chắn không tồn tại |
| 3 | Pagefile không hợp lệ: không có trên ổ hệ thống, hoặc quá nhỏ cho chế độ dump | Win32_PageFileUsage, cấu hình RAM | **Không** sửa tự động. Hướng dẫn; sửa pagefile chỉ khi bật cờ nâng cao và có xác nhận riêng |
| 4 | Ổ hệ thống thiếu dung lượng trống | `shutil.disk_usage` | Dọn ổ; có thể đề xuất chế độ nhỏ hơn |
| 5 | Đã bật nhưng ghi thất bại lúc sập | volmgr 161 (và các ID liên quan, xem 4.4) | Kiểm tra ổ đĩa/driver lưu trữ; đây là *bằng chứng* cho nhóm lỗi storage |
| 6 | Đã ghi được nhưng file bị dọn mất | Có Event 41 `BugcheckCode ≠ 0` nhưng không có file dump tương ứng, trong khi cấu hình "sẵn sàng" | Kiểm tra công cụ dọn dẹp (Storage Sense, Disk Cleanup, phần mềm tối ưu hệ thống). **Đây là giả thuyết cần xác minh, không phải kết luận.** |

Hệ quả thiết kế: nút "Bật ghi dump" chỉ giải quyết nhóm 1 (và một phần nhóm 2). Các nhóm còn lại phải được **chẩn đoán đúng và hướng dẫn**, không được hứa hẹn rằng bấm nút là xong.

### 1.2. Vì sao việc có dump quan trọng đến mức phải làm

Với một ca BSOD, file dump cho phép đọc stack và danh sách module nên nêu được driver nghi vấn (bằng chứng *mạnh*). Không có dump thì chỉ còn mã lỗi và tham số lấy từ Event Log (bằng chứng *yếu đến vừa*). Vì vậy, ngoài việc phân tích tốt hơn khi thiếu dữ liệu, giá trị lớn nhất là **bảo đảm lần sự cố sau sẽ có dump**.

### 1.3. Event Log bù được gì, không bù được gì

- **Bù được:** mã Bug Check và 4 tham số (Event 41, Event 1001), giờ tắt máy bất thường (Event 6008), dấu hiệu phần cứng độc lập (WHEA, Disk, stornvme, Ntfs), lý do ghi dump thất bại (volmgr).
- **Không bù được:** tên driver gây lỗi, stack, nội dung bộ nhớ. Do đó ở chế độ `log_only` kết luận phải dừng ở mức **"nhóm nghi ngờ"**, độ tin cậy trần ở mức thấp/trung bình, và **không được nêu tên một driver cụ thể** (đã là nguyên tắc hiện có của phần mềm; giữ nguyên).

### 1.4. Ba khái niệm phải tách bạch (nền tảng của thiết kế)

| Khái niệm | Câu hỏi | Cách xác định | Mức chắc chắn |
|---|---|---|---|
| **Cấu hình bật** | Registry có yêu cầu ghi dump không? | Đọc `CrashDumpEnabled` | Chắc chắn (đọc trực tiếp) |
| **Đủ điều kiện ghi** | Hệ thống có thể ghi được không? | Pagefile, dung lượng ổ, lỗi volmgr, đã khởi động lại sau khi đổi chưa | Suy luận |
| **Đã chứng minh ghi được** | Từng có dump thật chưa? | File dump tồn tại sau lần sập gần nhất, hoặc volmgr báo thành công | Bằng chứng thực tế |

Một máy "cấu hình bật" vẫn có thể "chưa đủ điều kiện", và "đủ điều kiện" vẫn chưa phải "đã chứng minh". Giao diện **không được** dùng chữ như "máy đã sẵn sàng 100%" khi mới chỉ qua kiểm tra cấu hình; phải ghi rõ mức đang đạt.

### 1.5. Hiện trạng mã nguồn và các lỗ hổng đã phát hiện (đối chiếu với v1.0.0; hãy mở file thực tế để xác nhận)

Nền tảng đã có trong `src/dumpanalyzer/collectors/dump_config.py`: `read_registry_crash_control`, `check_pagefile_status`, `check_disk_space_and_ram`, `check_volmgr_events`, `evaluate_readiness`, `backup_registry_crash_control`, `apply_automatic_dump`, và CLI `check-dump-config [--apply]`. Đây là nền tốt (mặc định chỉ đọc, yêu cầu xác nhận, sao lưu, không tự khởi động lại). Các lỗ hổng cần sửa:

| # | Lỗ hổng | Hậu quả |
|---|---|---|
| L1 | `evaluate_readiness` coi `CrashDumpEnabled is None` như "tắt hoàn toàn". `None` có thể do lỗi đọc registry (có `error`), không phải do tắt | Báo sai "KHÔNG GHI ĐƯỢC DUMP", và có thể dẫn đến ghi registry khi chưa hiểu tình trạng thật |
| L2 | `backup_registry_crash_control` chỉ lưu `CrashDumpEnabled`; khi giá trị ban đầu là `None` lại ghi `dword:00000000` | **Hoàn tác bằng file .reg sẽ đặt 0 (tắt) thay vì xóa giá trị**, tức khôi phục sai trạng thái. Chỉ lưu một giá trị nên không phục hồi được nếu sau này sửa thêm giá trị khác |
| L3 | `check_pagefile_status`: nếu lệnh PowerShell lỗi thì mặc định `has_system_drive_pagefile = True` (coi như ổn) | "Fail-open": không biết mà vẫn báo ổn. Cần trạng thái **không xác định** |
| L4 | `check_volmgr_events` đặt `has_failure_161` nếu bất kỳ sự kiện nào trong 10 sự kiện gần nhất là 161, kể cả khi sau đó đã có 162 thành công | Báo động cũ, không xét thứ tự thời gian. Ngoài ra `TimeCreated` từ `ConvertTo-Json` trên PowerShell 5.1 có dạng `/Date(...)/`, chưa chắc parse được |
| L5 | Ngưỡng dung lượng `RAM + 5 GB` áp dụng cho mọi chế độ | Quá khắt khe với chế độ Small/Automatic và quá lỏng cho Complete; cần ngưỡng theo chế độ, cấu hình được |
| L6 | Chưa tính `DedicatedDumpFile` (tệp dump riêng) khi đánh giá pagefile | Có thể báo sai thiếu pagefile |
| L7 | Không có khái niệm "đã đổi cấu hình nhưng chờ khởi động lại" | Sau khi bật, trạng thái vẫn hiện như cũ hoặc báo sẵn sàng sai |
| L8 | Chưa có hoàn tác, chưa có nhật ký thay đổi, chưa có kênh cho nhiều máy | Không kiểm soát được thay đổi trên đội máy |
| L9 | Chưa đối chiếu "số lần BSOD trong Event Log" với "số file dump tìm thấy" | Bỏ sót nhóm nguyên nhân số 6 |

---

## 2. NGUYÊN TẮC THIẾT KẾ BẮT BUỘC

| # | Nguyên tắc | Lý do |
|---|---|---|
| P1 | **Mặc định chỉ đọc.** Mọi thay đổi hệ thống cần hành động chủ động và xác nhận rõ của người dùng | Công cụ chạy với quyền Admin trên máy của người khác; sai sót phải ở mức tối thiểu |
| P2 | **Thay đổi tối thiểu.** Chỉ ghi giá trị `CrashDumpEnabled` (và nếu được cấu hình, `LogEvent`). Không sửa `AutoReboot`, `Overwrite`, `DumpFile`, `MinidumpDir`, pagefile... trừ chức năng nâng cao có cờ riêng (mục 5.5) | Giảm rủi ro ngoài ý muốn |
| P3 | **Không bao giờ tự khởi động lại máy**, không hẹn giờ khởi động lại | Máy có thể đang có người làm việc; quy tắc này đã có sẵn, giữ nguyên |
| P4 | **Hoàn tác được 100%**, kể cả trường hợp "giá trị ban đầu không tồn tại" | Khôi phục sai trạng thái (lỗ hổng L2) là không chấp nhận được |
| P5 | **Ba trạng thái, không phải hai**: biết / không biết / lỗi. "Không xác định" không được coi là "ổn" hay "hỏng" | Tránh kết luận khi thiếu dữ liệu (lỗ hổng L1, L3) |
| P6 | **Không tôn vinh cấu hình:** `sẵn sàng` ≠ `đã chứng minh`. Hiển thị mức đạt được | Xem 1.4 |
| P7 | **Tôn trọng lựa chọn có chủ đích:** máy đã đặt Complete/Kernel/Automatic thì không đổi. Máy ở Small (3) chỉ bị *cảnh báo*, không tự đổi hàng loạt | Có thể là chủ ý (ổ nhỏ) |
| P8 | **Nhật ký đầy đủ** cho mọi thay đổi (ai, máy nào, giá trị cũ/mới, kết quả, đường dẫn bản sao lưu) | Truy vết khi có sự cố |
| P9 | **Không lưu mật khẩu/thông tin xác thực**, không bật dịch vụ từ xa (WinRM...) thay người dùng | Bảo mật; chỉ dùng quyền của người đang chạy |
| P10 | **Một nguồn logic quyết định.** Ma trận quyết định (mục 3.3) nằm ở một nơi duy nhất trong mã (và cấu hình YAML), gói triển khai dùng lại hoặc có test đối chiếu | Tránh hai bản logic lệch nhau |
| P11 | **Không bịa.** Điều gì chưa kiểm chứng được trên Windows thật phải đánh dấu `[CẦN XÁC MINH]` trong mã, tài liệu và báo cáo, kèm cách kiểm tra | Người dùng sẽ tin vào kết quả |

---

## 3. MÔ HÌNH TRẠNG THÁI VÀ MA TRẬN QUYẾT ĐỊNH

### 3.1. Trạng thái tổng (`status`) — dùng mã, không dùng chuỗi tiếng Việt để so sánh

| Mã | Tên hiển thị | Màu | Ý nghĩa |
|---|---|---|---|
| `READY` | Sẵn sàng (theo cấu hình) | Xanh | Cấu hình bật, điều kiện đạt, không cảnh báo |
| `READY_PENDING_REBOOT` | Đã bật, chờ khởi động lại | Xanh nhạt/vàng | Đã đổi cấu hình, máy chưa khởi động lại kể từ lúc đổi |
| `ATTENTION` | Cần chú ý | Vàng | Có thể ghi dump nhưng có nguy cơ thất bại hoặc cấu hình chưa tối ưu |
| `BLOCKED` | Không ghi được dump | Đỏ | Có ít nhất một lý do chặn chắc chắn |
| `UNKNOWN` | Không xác định | Xám | Không đọc được dữ liệu cần thiết |

Thêm trường riêng `proof_level`: `none` / `evidence_of_success` (volmgr 162 hoặc tìm thấy file dump sau lần sập gần nhất) — hiển thị cạnh trạng thái, đúng như 1.4.

### 3.2. Mã lý do (`reason_codes`, danh sách) — mỗi mã có mức `blocking | warning | info`

| Mã | Mức | Điều kiện |
|---|---|---|
| `DUMP_DISABLED` | blocking | `CrashDumpEnabled == 0` |
| `DUMP_VALUE_MISSING` | blocking* | Khóa đọc được nhưng giá trị `CrashDumpEnabled` **không tồn tại** (*xem ghi chú) |
| `REGISTRY_UNREADABLE` | unknown | Lỗi đọc registry (có `error`) → trạng thái `UNKNOWN` |
| `DUMP_MODE_SMALL` | warning | `CrashDumpEnabled == 3` |
| `PAGEFILE_MISSING` | blocking | Không có pagefile trên ổ hệ thống **và** không có `DedicatedDumpFile` hợp lệ |
| `PAGEFILE_UNKNOWN` | unknown | Không xác định được pagefile (lỗi lệnh) |
| `PAGEFILE_TOO_SMALL` | warning | Nhỏ hơn mức tối thiểu của chế độ (ngưỡng cấu hình được, xem 9.3) |
| `DISK_LOW` | warning | Dung lượng trống ổ hệ thống dưới ngưỡng theo chế độ |
| `VOLMGR_FAILURE_RECENT` | warning | Sự kiện thất bại volmgr **mới hơn** sự kiện thành công gần nhất (hoặc chưa từng thành công) |
| `DUMP_FILES_MISSING` | warning | Đối chiếu Event 41 với file dump cho thấy thiếu (mục 8.2) |
| `PENDING_REBOOT` | info | Đã đổi cấu hình, chưa khởi động lại |
| `NOT_ADMIN` | info | Chạy không có quyền Admin nên một số kiểm tra bị giới hạn |

\* **Ghi chú `DUMP_VALUE_MISSING`:** hành vi mặc định của Windows khi giá trị này vắng mặt chưa được xác minh trong tài liệu này. `[CẦN XÁC MINH]` Hãy coi đây là mức `blocking` *về mặt chẩn đoán* nhưng khi hành động bật thì xử lý như "chưa có cấu hình" (được phép ghi 7 sau xác nhận). Không được coi `None` do lỗi đọc là `DUMP_VALUE_MISSING`; phải tách bằng trường `error`.

### 3.3. Ma trận quyết định cho hành động "Bật ghi dump" (nguồn logic duy nhất)

Đầu vào: giá trị hiện tại của `CrashDumpEnabled`, kết quả đọc (ok/lỗi), quyền Admin, dung lượng trống, pagefile.

| Hiện trạng | Hành động mặc định của nút | Ghi chú |
|---|---|---|
| Đọc registry **lỗi** | **Không làm gì**, báo `UNKNOWN`, hiển thị lỗi | P5 |
| `0` hoặc **không tồn tại** | **Cho phép bật** về chế độ đích | Chế độ đích xem dưới |
| `1`, `2`, `7` | **Không đổi.** Báo "Đã bật" (và các cảnh báo khác nếu có) | P7 |
| `3` (Small) | **Không tự đổi.** Cảnh báo; nút phụ "Nâng cấp lên Automatic" có xác nhận riêng, mặc định **ẩn trong bật hàng loạt** | P7 |
| Không phải Admin | Nút bị khóa, nêu lý do | |
| Đã ở `READY` | Nút bị khóa ("Đã sẵn sàng") | Idempotent |
| Có lý do `blocking` **không** thuộc registry (ví dụ `PAGEFILE_MISSING`) | Nút "Bật" vẫn đặt được registry nhưng hộp thoại **phải cảnh báo rõ**: "Máy vẫn chưa ghi được dump vì <lý do>"; trạng thái sau đó vẫn là `BLOCKED` | Không hứa hẹn quá mức |

**Chế độ đích** (`dump_readiness.target_mode`, mặc định `7`) kèm quy tắc theo dung lượng (có thể tắt bằng cấu hình):
- Dung lượng trống đạt ngưỡng của chế độ 7 → đặt `7`.
- Không đạt nhưng đạt ngưỡng tối thiểu của chế độ Small (mặc định 2 GB) → **chỉ đề xuất** `3` trong hộp thoại, không tự chọn thay người dùng.
- Dưới ngưỡng tối thiểu → không bật; hướng dẫn dọn ổ.

---

## 4. PHẦN A — CỦNG CỐ BỘ KIỂM TRA SẴN SÀNG (`collectors/dump_config.py`)

Giữ nguyên tên hàm công khai hiện có (tương thích với CLI/GUI/test cũ); thêm hàm mới và trường mới. Nhánh không phải Windows tiếp tục trả dữ liệu mô phỏng để test chạy trên Linux.

### 4.1. Trả về có cấu trúc, tách "không có" và "lỗi" (sửa L1, L3)

- `read_registry_crash_control()`: thêm `value_present: bool`, `read_ok: bool`; `CrashDumpEnabled` là `None` **chỉ** khi giá trị không tồn tại *và* đọc thành công; nếu lỗi → `read_ok=False`, `error` có nội dung. Đọc thêm `DedicatedDumpFile`, `DumpFileSize`, `LogEvent` (chỉ đọc, phục vụ đánh giá).
- `check_pagefile_status()`: thêm `state` ∈ {`ok`, `missing`, `unknown`}, `system_drive_size_mb`, `automatic_managed`. Khi lệnh lỗi hoặc timeout → `state="unknown"` (không mặc định `ok`). Có tính `DedicatedDumpFile`.
- Chạy PowerShell: dùng cùng cách dựng lệnh an toàn đã thống nhất ở Đợt 02 (nhóm C): không dùng `foreach (...) {} |`, đặt `[Console]::OutputEncoding = UTF8`, có timeout cấu hình, và **báo lỗi thay vì im lặng**.

### 4.2. Xử lý thời gian và thứ tự sự kiện volmgr (sửa L4)

- Lấy `TimeCreated` ở dạng ISO 8601 ổn định (ví dụ trong PowerShell: `$_.TimeCreated.ToUniversalTime().ToString('o')`), không phụ thuộc định dạng JSON mặc định. Lưu UTC theo `core/timeutil.py`.
- Đánh giá theo **thứ tự thời gian**: `VOLMGR_FAILURE_RECENT` chỉ khi sự kiện thất bại gần nhất **mới hơn** sự kiện thành công gần nhất, hoặc chưa từng có thành công. Thêm cửa sổ tra cứu cấu hình được (`volmgr_lookback_days`, mặc định 180) và lấy nhiều hơn 10 sự kiện.

### 4.3. Ngưỡng theo chế độ, cấu hình được (sửa L5)

Đưa ngưỡng vào `config/rules/dump_readiness.yaml` (mục 9.3), **không hard-code**. Mặc định đề xuất:
- Free disk tối thiểu: chế độ `7`/`2` = max(RAM_GB + 5, 10) (giữ hành vi hiện tại); chế độ `1` (Complete) = RAM_GB + 5; chế độ `3` = 2 GB.
- Pagefile tối thiểu theo chế độ: **`[CẦN XÁC MINH]` theo tài liệu Microsoft hiện hành** (Complete: kích thước RAM cộng khoảng 257 MB là con số được tài liệu Microsoft nêu từ lâu; các chế độ còn lại cần tra cứu lại). Nếu không xác minh được từ nguồn chính thức, **chỉ triển khai các kiểm tra chắc chắn** (có/không có pagefile trên ổ hệ thống; Complete = RAM + 257 MB) và để các ngưỡng còn lại là cảnh báo cấu hình được, mặc định tắt. Ghi rõ nguồn đã dùng trong báo cáo.

### 4.4. Mở rộng chỉ báo trong Event Log (cấu hình được)

Ngoài volmgr 161/162, đưa danh sách ID vào YAML để người dùng sửa được, **không hard-code**:
- Ứng viên thất bại khi chuẩn bị/ghi dump: volmgr `45`, `46`, `49` (cấu hình pagefile cho dump thất bại; thường kèm thông điệp về pagefile trên phân vùng khởi động). `[CẦN XÁC MINH]` ID và nội dung trên Windows thật.
- Đọc đúng provider và ID bằng `-FilterHashtable`.

### 4.5. Trạng thái chờ khởi động lại (sửa L7)

- Thu `last_boot_time` (UTC) từ `Win32_OperatingSystem.LastBootUpTime`.
- Mọi lần phần mềm đổi cấu hình ghi bản ghi vào bảng `dump_config_change` (mục 9.1) với `changed_at`. Nếu `last_boot_time < changed_at` → `PENDING_REBOOT`, trạng thái `READY_PENDING_REBOOT`. Khi `last_boot_time >= changed_at` thì bỏ cờ.
- `[CẦN XÁC MINH]` Giả định "đổi `CrashDumpEnabled` cần khởi động lại mới có hiệu lực" là cách hiểu thận trọng; hãy xác nhận bằng thử nghiệm trên máy ảo thử (mục 10.3) và ghi kết quả. Cho đến khi xác nhận, cứ coi là cần khởi động lại.

### 4.6. Hàm tổng hợp

Thêm `collect_dump_readiness() -> dict` gom: registry, pagefile, disk, volmgr, last_boot_time, quyền Admin, thông tin máy (tên, phiên bản Windows), và kết quả `evaluate_readiness_v2(...)` trả về:

```python
{
  "status": "READY|READY_PENDING_REBOOT|ATTENTION|BLOCKED|UNKNOWN",
  "proof_level": "none|evidence_of_success",
  "reason_codes": [{"code": "...", "level": "blocking|warning|info|unknown", "detail": "..."}],
  "summary": "...",            # tiếng Việt
  "recommendations": ["..."],  # tiếng Việt, tương ứng reason_codes
  "enable_action": {"allowed": bool, "blocked_by": ["..."], "target_mode": 7, "needs_confirm_notes": ["..."]},
}
```

`evaluate_readiness` cũ giữ nguyên chữ ký, gọi bản mới và ánh xạ lại về cấu trúc cũ (để CLI/GUI/test hiện có không vỡ). Cập nhật các test cũ nào cần theo hành vi đúng hơn (L1, L3, L4), và nêu rõ trong báo cáo test nào đã đổi và vì sao.

---

## 5. PHẦN B — HÀNH ĐỘNG BẬT GHI DUMP (LOCAL), SAO LƯU, HOÀN TÁC, NHẬT KÝ

### 5.1. Hàm `enable_crash_dump(target_mode=None, confirmed=False, actor=None, method="local")`

Thay/bao `apply_automatic_dump` (giữ `apply_automatic_dump` như lớp vỏ gọi hàm mới để tương thích). Trình tự **bắt buộc**, dừng ngay khi một bước thất bại:

1. `confirmed` phải là `True`; nếu không → trả về `success=False` (không làm gì).
2. Phải là Admin; nếu không → thông báo tiếng Việt, không làm gì.
3. Thu `collect_dump_readiness()`; áp dụng **ma trận 3.3**. Nếu không được phép → trả về lý do, không ghi gì.
4. **Sao lưu đầy đủ** (5.2). Nếu sao lưu lỗi → hủy.
5. Ghi **đúng một giá trị** `CrashDumpEnabled = target_mode` (kiểu `REG_DWORD`) vào khóa `CrashControl`. (Nếu cấu hình `set_log_event=true` thì chỉ khi `LogEvent` đang **không tồn tại** mới đặt `LogEvent=1`; mặc định `false`.)
6. **Đọc lại** giá trị vừa ghi để xác nhận (read-after-write). Nếu khác mong đợi → coi là thất bại, tự hoàn tác từ bản sao lưu, báo lỗi.
7. Ghi nhật ký (5.4) và trả về kết quả: `success`, `message`, `backup_path`, `reboot_required=True`.
8. **Không** khởi động lại, **không** hẹn giờ khởi động lại, **không** đụng giá trị khác.

### 5.2. Sao lưu (sửa L2)

Mỗi lần bật tạo **hai** tệp trong `backup/` (hoặc thư mục cấu hình `dump_readiness.backup_dir`), tên `CrashControl_<hostname>_<YYYYMMDD_HHMMSS>.*`:

1. `.json` — **nguồn sự thật để hoàn tác**: ghi *toàn bộ* các giá trị hiện có trong khóa `CrashControl` (tên, kiểu, dữ liệu) và danh sách tên giá trị **chưa tồn tại** (ví dụ `"CrashDumpEnabled": {"present": false}`). Có `schema_version`, `hostname`, `created_at_utc`, `tool_version`.
2. `.reg` — bản dự phòng cho người dùng mở bằng tay: xuất **toàn bộ khóa** (ví dụ `reg export "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" <file> /y`). **Không** được ghi `dword:00000000` cho giá trị không tồn tại. Nếu tự sinh nội dung .reg thì giá trị vốn không có phải ghi bằng cú pháp xóa (`"CrashDumpEnabled"=-`).

Tính SHA256 của hai tệp và lưu vào nhật ký.

### 5.3. Hoàn tác `rollback_crash_dump(backup_json_path, confirmed=False)`

- Yêu cầu Admin và xác nhận.
- Đọc tệp `.json`; với mỗi giá trị **đã tồn tại trước đó** → ghi lại đúng kiểu/giá trị; với giá trị **không tồn tại trước đó** → `DeleteValue` (xử lý lỗi "không có" là bình thường).
- Chỉ đụng các giá trị mà phần mềm từng thay đổi (ghi trong nhật ký); không ghi đè các giá trị khác người dùng có thể đã tự sửa sau đó.
- Đọc lại kiểm tra, ghi nhật ký, cho biết cần khởi động lại.

### 5.4. Nhật ký thay đổi

- Tệp `logs/dump_config_changes.jsonl` (mỗi dòng một JSON) **và** bảng CSDL `dump_config_change` (mục 9.1): `changed_at_utc`, `hostname`, `actor` (tên người dùng Windows đang chạy), `method` (`local` | `remote` | `package`), `action` (`enable` | `rollback` | `upgrade_small_to_auto` | `pagefile_fix`), `old_values`, `new_values`, `backup_path`, `result`, `message`, `reboot_required`.
- Không ghi thông tin xác thực. Nhật ký chỉ thêm vào (append-only).

### 5.5. Chức năng nâng cao tùy chọn: sửa pagefile (mặc định TẮT)

Chỉ làm khi `dump_readiness.allow_pagefile_fix = true` trong `settings.yaml` (mặc định `false`) **và** có xác nhận riêng, tách khỏi xác nhận bật dump:
- Thao tác duy nhất: bật "tự động quản lý pagefile" (ví dụ qua `Win32_ComputerSystem.AutomaticManagedPagefile = True`). `[CẦN XÁC MINH]` cách thực hiện chính xác và yêu cầu khởi động lại trên Windows thật.
- Sao lưu trạng thái cũ (cùng cơ chế 5.2), ghi nhật ký, báo cần khởi động lại.
- Nếu không thể xác minh/kiểm thử, **không triển khai** mục này, chỉ để lại khung (nút ẩn) và nêu trong báo cáo. Hướng dẫn thủ công đã có sẵn trong `recommendations`.

---

## 6. PHẦN C — GIAO DIỆN VÀ CLI

### 6.1. CLI (`cli.py`) — giữ `check-dump-config [--apply]`, thêm:

| Lệnh | Quyền | Chức năng |
|---|---|---|
| `dump-readiness [--json] [--out <file>]` | Không cần Admin (một số kiểm tra giới hạn, ghi chú `NOT_ADMIN`) | In/ghi báo cáo sẵn sàng của máy này (định dạng JSON ở 9.2) |
| `dump-enable [--yes] [--mode 7\|3]` | Admin | Thực hiện 5.1. Không có `--yes` thì hỏi xác nhận trên console và hiển thị đầy đủ nội dung thay đổi |
| `dump-rollback --backup <file.json> [--yes]` | Admin | Thực hiện 5.3 |
| `dump-package --out <thư mục>` | Không cần Admin | Tạo gói triển khai (7.3) |
| `dump-fleet --dir <thư mục chia sẻ> [--export <xlsx>]` | Không cần Admin | Đọc các tệp JSON báo cáo của đội máy và tổng hợp (7.2) |
| `dump-remote-check` / `dump-remote-enable` | Admin/quyền miền | Chỉ khi làm kênh từ xa (7.4) |

Mã thoát thống nhất với Hotfix 02: 0 thành công; 1 lỗi không mong đợi; 3 thiếu quyền; 4 người dùng không xác nhận/hủy; 5 bị chặn bởi ma trận quyết định.

### 6.2. GUI — tab mới "Sẵn sàng ghi dump" (`gui/tab_dump_readiness.py`, đăng ký trong `main_window.py`)

**Khu vực 1 — Máy này**
- Huy hiệu trạng thái (màu theo 3.1) + dòng `proof_level` ("Chưa từng ghi dump được bằng chứng" / "Đã có dump hoặc volmgr 162 thành công").
- Danh sách lý do và khuyến nghị (tiếng Việt, theo `reason_codes`).
- Thông tin: chế độ dump hiện tại, pagefile, dung lượng trống/RAM, lần khởi động gần nhất, số BSOD (Event 41) và số file dump tìm thấy trong 90 ngày (mục 8.2).
- Nút:
  - **[Kiểm tra lại]** — luôn có.
  - **[Bật ghi dump]** — chỉ bật khi `enable_action.allowed`; nếu khóa, tooltip nêu đúng lý do (không phải Admin / đã sẵn sàng / bị chặn bởi ...). Khi bấm: hộp thoại xác nhận (mẫu ở Phụ lục A), chạy trên luồng nền (dùng cơ chế `worker.py` hiện có, không làm đơ giao diện), rồi hiện kết quả và cập nhật trạng thái.
  - **[Hoàn tác thay đổi gần nhất]** — chọn từ danh sách bản sao lưu, có xác nhận.
  - **[Xuất gói triển khai]** — tạo gói (7.3).
  - **[Mở thư mục sao lưu/nhật ký]**.
- Hộp cảnh báo nổi bật sau khi bật: "Đã bật. **Cần khởi động lại máy** để có hiệu lực. Phần mềm không tự khởi động lại."

**Khu vực 2 — Đội máy** (chỉ hiển thị khi có dữ liệu; mục 7)
- Bảng: ☐ Chọn | Tên máy | Trạng thái | Lý do chính | Chế độ dump | Chờ khởi động lại | Báo cáo lần cuối (đánh dấu **cũ** nếu quá `stale_days`) | Nguồn (chia sẻ/từ xa).
- Bộ lọc nhanh (Chưa sẵn sàng / Chờ khởi động lại / Báo cáo cũ) và ô tìm tên máy.
- Nút: **[Nạp báo cáo từ thư mục chia sẻ]**, **[Quét từ xa]** (chỉ nếu bật kênh từ xa), **[Bật cho máy đã chọn]**, **[Xuất gói triển khai cho máy đã chọn]**, **[Xuất Excel]**.
- **[Bật cho máy đã chọn]**: chỉ xử lý máy mà ma trận 3.3 cho phép. Hộp thoại xác nhận liệt kê **tên từng máy** và việc sẽ làm, có ô tích "Tôi hiểu thay đổi này cần khởi động lại từng máy và sẽ được ghi nhật ký". Không có tùy chọn bật hàng loạt cho "nâng cấp Small → Automatic" (P7).

### 6.3. Hiển thị trong kết luận phân tích

Trong Tab kết luận và báo cáo (HTML/Excel), khi máy ở trạng thái khác `READY` hoặc kết luận dựa vào `log_only`:
- Thêm hộp cố định đầu mục: "**Máy chưa sẵn sàng ghi dump**" kèm lý do và đường dẫn đến Tab "Sẵn sàng ghi dump".
- Thêm mục vào danh sách "bước kiểm tra tiếp theo" (nếu Đợt 03 đã có `next_steps.yaml`, thêm khóa ở đó; nếu chưa, hiển thị trực tiếp từ `recommendations`).

---

## 7. PHẦN D — ĐỘI MÁY

**Câu hỏi thiết kế:** phần mềm hiện chạy cục bộ và chế độ batch chỉ phân tích *file dump* trong một thư mục. Không có kênh truy cập từ xa. Vì vậy, "nút bật cho các máy chưa bật" phải được hiện thực bằng ba kênh có mức rủi ro tăng dần. **Làm theo thứ tự 7.1 → 7.2 → 7.3; kênh 7.4 là tùy chọn và chỉ làm sau khi ba kênh trước đã xong.**

### 7.1. Kênh 1 — Báo cáo từ từng máy (khuyến nghị, không cần quyền từ xa)

Mỗi máy tự tạo báo cáo bằng `DumpAnalyzer-cli.exe dump-readiness --json --out <thư mục chia sẻ>\<TÊN_MÁY>.json` (chạy tay, bằng GPO startup script, hoặc tác vụ định kỳ). Tệp JSON theo đặc tả 9.2; **ghi đè tệp cũ** của cùng máy (giữ `collected_at_utc`).
- Ưu điểm: không cần WinRM, không cần mật khẩu, tận dụng thư mục chia sẻ có sẵn.
- Giới hạn cần ghi trong tài liệu: dữ liệu là ảnh chụp tại thời điểm chạy, có thể cũ.

### 7.2. Kênh 2 — Tổng hợp đội máy (đọc, `dump-fleet`)

- Đọc tất cả `*.json` trong thư mục; **kiểm tra hợp lệ từng tệp** (đúng `schema_version`, đủ trường bắt buộc, kích thước hợp lý). Tệp hỏng bỏ qua và liệt kê trong phần "tệp không đọc được", không làm sập.
- Lưu vào bảng `dump_readiness` (mục 9.1), xóa trùng theo (tên máy, `collected_at_utc`).
- Đánh dấu báo cáo cũ nếu `collected_at_utc` cách hiện tại hơn `dump_readiness.stale_days` (mặc định 14).
- Thống kê: số máy theo trạng thái, **tỷ lệ máy `READY`**, danh sách máy `BLOCKED`/`UNKNOWN`/chờ khởi động lại, top lý do (đếm theo `reason_codes`).
- Xuất Excel (sheet "Tổng quan", "Chi tiết từng máy", "Cần xử lý ngay").
- Nếu Đợt 03 (nhập CSV danh sách thiết bị) đã có: đối chiếu để liệt kê **máy có trong danh sách nhưng chưa có báo cáo** (không biết trạng thái) — nhóm này cần xếp riêng vì "không có báo cáo" ≠ "ổn".

### 7.3. Kênh 3 — Gói triển khai bật dump (`dump-package --out <thư mục>`)

Tạo một thư mục chứa:
- `Enable-CrashDump.ps1` — tập lệnh PowerShell **idempotent** (chạy nhiều lần cho kết quả như một lần), tuân thủ đúng ma trận 3.3 (chỉ ghi khi giá trị là `0`/không tồn tại; không đổi `1`,`2`,`7`,`3`); có `-WhatIf`; sao lưu giống 5.2 (JSON + .reg) vào `%ProgramData%\DumpAnalyzer\backup`; ghi nhật ký vào `%ProgramData%\DumpAnalyzer\logs`; **ghi báo cáo JSON** (9.2) vào thư mục chia sẻ nếu có tham số `-ReportDir`; không chứa lệnh khởi động lại hay đổi cấu hình khác; thoát với mã khác 0 khi lỗi.
- `Rollback-CrashDump.ps1` — hoàn tác theo tệp sao lưu `.json` (đúng nguyên tắc P4, kể cả xóa giá trị vốn không tồn tại).
- `README_TRIEN_KHAI.txt` (tiếng Việt): 3 cách dùng — chạy tay trên từng máy bằng quyền Admin; GPO (Computer Configuration → Policies → Windows Settings → Scripts → Startup, hoặc Group Policy Preferences → Registry); công cụ quản lý máy hiện có của công ty (RMM/Intune/PDQ...). Nêu rõ: **không tự khởi động lại**, thay đổi chỉ có hiệu lực sau lần khởi động lại tiếp theo.
- Ưu tiên một nguồn logic (P10): nếu `DumpAnalyzer-cli.exe` được đặt trong cùng thư mục chia sẻ, để `Enable-CrashDump.ps1` có chế độ `-UseCli` gọi `dump-enable --yes --json`; chế độ mặc định là tự chứa (không cần exe) và phải có **test đối chiếu** (10.1) bảo đảm cùng bảng quyết định.
- Sinh thêm danh sách `chi_tiet_may_can_xu_ly.csv` nếu xuất từ bảng đội máy (chỉ các máy đã chọn).

Mẫu khung tập lệnh ở Phụ lục B (tham khảo; phải kiểm thử trên Windows thật trước khi coi là hoàn thành).

### 7.4. Kênh 4 (TÙY CHỌN) — Từ xa qua PowerShell Remoting

Chỉ làm sau khi 7.1–7.3 hoàn tất và có xác nhận của người dùng. Ràng buộc:
- Chỉ dùng quyền của người đang chạy (Kerberos/NTLM tích hợp); **không** lưu hay nhập mật khẩu trong phần mềm (P9). Không tự bật WinRM/mở tường lửa thay người dùng.
- Danh sách máy: tệp văn bản/CSV do người dùng cung cấp (không tự dò mạng).
- `dump-remote-check`: chỉ **đọc** (cùng bộ kiểm tra 4.x qua `Invoke-Command`), có `Test-WSMan` trước, giới hạn đồng thời (`remote_max_parallel`, mặc định 5), timeout từng máy, **cô lập lỗi theo máy** (một máy lỗi không làm hỏng cả lượt). Kết quả đi vào cùng bảng `dump_readiness` với nguồn `remote`.
- `dump-remote-enable`: chỉ cho các máy được chọn, áp dụng đúng ma trận 3.3 phía máy đích, ghi nhật ký cả phía người điều khiển lẫn phía máy đích, **không khởi động lại**.
- Mọi thứ trong kênh này `[CẦN XÁC MINH]` trên môi trường thật; nếu không có môi trường kiểm thử, **chỉ triển khai khung và test bằng giả lập**, ghi rõ "chưa kiểm chứng từ xa".

---

## 8. PHẦN E — PHÂN TÍCH KHI KHÔNG CÓ DUMP (`log_only`) VÀ PHÁT HIỆN "DUMP BỊ MẤT"

### 8.1. Quy tắc suy luận chặt chẽ cho `log_only`

Kiểm tra mã hiện có (`correlator.detect_log_only_crashes`, `scorer`, `bugcheck_rules.yaml`) đã làm được gì rồi **chỉ bổ sung phần thiếu**, không viết lại:

1. **Nguồn mã lỗi theo độ ưu tiên:** Event 41 (`BugcheckCode` + tham số) → Event 1001 (đọc từ `EventData`, không dùng regex tiếng Anh, theo Đợt 02 nhóm E) → không có. `[CẦN XÁC MINH]` Trong Event 41, `BugcheckCode` thường là **số thập phân** (ví dụ 159 tương ứng 0x9F) còn tham số là chuỗi hex; hãy chuyển đổi và kiểm tra bằng dữ liệu thật; lưu mã dưới dạng chuẩn `0x..` như bảng `crash` hiện dùng.
2. **`BugcheckCode = 0`:** **không phải BSOD** (mất nguồn, giữ nút nguồn, treo cứng, lỗi nguồn). Phải phân loại thành `non_bsod_reset`, không dùng luật chấm điểm cho mã lỗi cụ thể; dùng riêng pattern "mất nguồn" (đã sửa điều kiện ở Đợt 02 A4).
3. **Độ tin cậy trần:** không bao giờ vượt "trung bình" nếu chỉ có mã lỗi từ Event Log; thông điệp luôn nêu rõ "chỉ dựa trên Event Log, không có dump". Nếu Đợt 03 đã có `confidence_policy` thì dùng cơ chế đó (mã lỗi đơn lẻ = bằng chứng yếu); nếu chưa, giữ trần hiện có và không nới.
4. **Không nêu tên driver cụ thể** ở chế độ này (giữ nguyên tắc cũ).
5. **Giờ sập** dùng quy tắc của Đợt 02 nhóm D (không lấy giờ Event 41 làm giờ sập nếu có cách tốt hơn).

### 8.2. Đối chiếu "số BSOD" với "số file dump" (sửa L9 — nhóm nguyên nhân 6)

Hàm mới `compute_dump_gap(days=90)` trong `dump_config.py` (hoặc `engine/`):
- `expected` = số lần sập có `BugcheckCode ≠ 0` trong Event 41 trong `days` ngày (gộp các sự kiện trùng cách nhau dưới 10 phút, như `correlator` đang làm).
- `found` = số file dump (từ `dump_finder`) có thời gian nằm trong cùng khoảng và khớp từng lần sập (cửa sổ khớp cấu hình được, mặc định ±15 phút).
- `missing = expected - matched`. Nếu `missing > 0` **và** cấu hình ở trạng thái `READY`/`READY_PENDING_REBOOT` → thêm `DUMP_FILES_MISSING` (warning) với chi tiết từng lần sập không có dump.
- Lời lẽ trong giao diện phải là **giả thuyết cần xác minh**: "Có thể do công cụ dọn dẹp xóa file dump, ổ đầy lúc sập, hoặc lỗi ghi dump (volmgr). Hãy kiểm tra Storage Sense/Disk Cleanup/phần mềm tối ưu hệ thống". Không khẳng định nguyên nhân.
- Không tính các lần sập trước khi phần mềm đổi cấu hình (nếu có bản ghi `dump_config_change`), để không báo "thiếu dump" cho giai đoạn dump còn tắt.

### 8.3. Khuyến nghị tự động đi kèm kết luận

Khi `log_only` hoặc `status != READY`: luôn kèm khuyến nghị "Bật ghi dump" (nếu phù hợp), hoặc nêu đúng việc cần sửa trước (pagefile, ổ đĩa...). Văn bản nằm trong YAML `next_steps` hoặc `dump_readiness.yaml` để người dùng chỉnh được.

---

## 9. DỮ LIỆU VÀ CẤU HÌNH

### 9.1. CSDL (migration tương thích ngược trong `storage/db.py`, **và** cập nhật `schema.sql` cho cài mới)

```sql
CREATE TABLE IF NOT EXISTS dump_readiness (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT NOT NULL,
  collected_at_utc TEXT NOT NULL,
  source TEXT NOT NULL,                  -- local | share_json | remote
  status TEXT NOT NULL,                  -- READY | READY_PENDING_REBOOT | ATTENTION | BLOCKED | UNKNOWN
  proof_level TEXT NOT NULL DEFAULT 'none',
  crash_dump_enabled INTEGER,            -- NULL nếu không tồn tại hoặc không đọc được
  registry_read_ok INTEGER NOT NULL DEFAULT 1,
  pagefile_state TEXT,                   -- ok | missing | unknown
  free_disk_gb REAL,
  ram_gb REAL,
  last_boot_time_utc TEXT,
  pending_reboot INTEGER NOT NULL DEFAULT 0,
  reason_codes_json TEXT,
  raw_json TEXT,
  UNIQUE(hostname, collected_at_utc)
);

CREATE TABLE IF NOT EXISTS dump_config_change (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT NOT NULL,
  changed_at_utc TEXT NOT NULL,
  actor TEXT,
  method TEXT NOT NULL,                  -- local | remote | package
  action TEXT NOT NULL,                  -- enable | rollback | upgrade_small_to_auto | pagefile_fix
  old_values_json TEXT,
  new_values_json TEXT,
  backup_path TEXT,
  result TEXT NOT NULL,                  -- success | failed | cancelled | blocked
  message TEXT,
  reboot_required INTEGER NOT NULL DEFAULT 0
);
```

`schema.sql` phải được đóng gói đúng như Hotfix 01. Kiểm tra không phá dữ liệu cũ (test migration từ DB v1.0.0).

### 9.2. Định dạng tệp báo cáo của một máy (JSON, `schema_version = 1`)

```json
{
  "schema_version": 1,
  "tool_version": "1.x.x",
  "hostname": "PC-KT-05",
  "collected_at_utc": "2026-11-03T08:15:00Z",
  "os": {"caption": "Microsoft Windows 11 Pro", "build": "22631"},
  "is_admin": true,
  "registry": {"read_ok": true, "crash_dump_enabled": 0, "value_present": true,
               "dedicated_dump_file": null, "log_event": 1},
  "pagefile": {"state": "ok", "system_drive_size_mb": 4096, "automatic_managed": true},
  "disk": {"system_drive": "C:\\", "free_gb": 85.3},
  "ram_gb": 16.0,
  "volmgr": {"last_failure_utc": null, "last_success_utc": null},
  "last_boot_time_utc": "2026-11-01T01:02:03Z",
  "result": {
    "status": "BLOCKED",
    "proof_level": "none",
    "reason_codes": [{"code": "DUMP_DISABLED", "level": "blocking"}],
    "pending_reboot": false
  }
}
```

Quy tắc đọc: bỏ qua trường lạ, chấp nhận thiếu trường tùy chọn (đánh `UNKNOWN` cho phần thiếu), từ chối tệp sai `schema_version` hoặc quá lớn (ví dụ > 256 KB). Không chứa thông tin cá nhân ngoài tên máy.

### 9.3. Cấu hình

`config/settings.yaml` (khóa mới, thiếu thì dùng mặc định):

```yaml
dump_readiness:
  target_mode: 7
  set_log_event: false
  allow_pagefile_fix: false
  backup_dir: backup
  share_dir: ""            # thư mục chia sẻ chứa báo cáo JSON của đội máy
  stale_days: 14
  volmgr_lookback_days: 180
  dump_gap_days: 90
  dump_gap_match_minutes: 15
  remote_enabled: false
  remote_max_parallel: 5
```

`config/rules/dump_readiness.yaml` (mới): ngưỡng dung lượng/pagefile theo chế độ, danh sách ID sự kiện volmgr, văn bản khuyến nghị tiếng Việt cho từng mã lý do. Thêm vào `validate-rules`; thêm tài liệu vào `docs/RULES_GUIDE.md`.

---

## 10. KIỂM THỬ

### 10.1. Tự động (chạy được trên Linux, không phụ thuộc Windows)

1. **Ma trận quyết định:** bảng tham số hóa cho mọi dòng ở 3.3 (đọc lỗi; `0`; không tồn tại; `1`,`2`,`7`; `3`; không Admin; đã `READY`; có lý do chặn ngoài registry). Kiểm tra `enable_action.allowed` và thông điệp.
2. **Tách "None do lỗi" với "không tồn tại"** (L1): `read_ok=False` → `UNKNOWN`, không cho phép ghi.
3. **Pagefile `unknown`** không bị coi là `ok` (L3). **Thứ tự volmgr** (L4): 161 rồi 162 → không cảnh báo; 162 rồi 161 → cảnh báo; chỉ có 161 → cảnh báo.
4. **Sao lưu/hoàn tác** (L2): giả lập registry bằng một lớp giả (không đụng registry thật); với giá trị ban đầu `0`, `3`, **không tồn tại**: bật rồi hoàn tác phải đưa về đúng trạng thái ban đầu (kể cả xóa giá trị).
5. **Read-after-write thất bại** → tự hoàn tác và báo lỗi.
6. **Idempotent:** bật hai lần chỉ thay đổi một lần, lần hai báo "đã sẵn sàng", không tạo thêm bản sao lưu.
7. **Không có đường nào khởi động lại máy:** quét mã nguồn và gói triển khai, không có `shutdown`, `Restart-Computer`, `Stop-Computer`, `InitiateSystemShutdown`.
8. **Chờ khởi động lại:** `last_boot_time < changed_at` → `READY_PENDING_REBOOT`; sau đó giả lập khởi động lại → `READY`.
9. **Báo cáo JSON:** ghi/đọc vòng tròn; tệp hỏng, sai phiên bản, quá lớn bị bỏ qua mà không làm sập `dump-fleet`; báo cáo cũ được đánh dấu.
10. **Gói triển khai:** sinh được đủ tệp; `Enable-CrashDump.ps1` có `-WhatIf`, có sao lưu, không chứa lệnh khởi động lại; **test đối chiếu bảng quyết định** (so khớp các trường hợp 3.3 giữa logic Python và văn bản/điều kiện trong tập lệnh bằng kiểm tra tĩnh các nhánh chính).
11. **Dump gap (8.2):** các tình huống đủ/thiếu dump, loại trừ giai đoạn trước khi đổi cấu hình, gộp sự kiện trùng.
12. **Event 41:** mã thập phân chuyển thành hex đúng; `BugcheckCode = 0` phân loại `non_bsod_reset` và không bị chấm theo mã lỗi cụ thể.
13. **GUI (offscreen):** nút "Bật ghi dump" khóa/mở đúng theo trạng thái; hộp thoại xác nhận bắt buộc (mock) — không có xác nhận thì không gọi hàm ghi; bảng đội máy hiển thị đúng và lọc đúng.
14. **Migration:** mở CSDL v1.0.0 → tự nâng cấp, dữ liệu cũ nguyên vẹn.
15. `python -m ruff check src` và `python -m pytest -q` PASS; `selftest` (Hotfix 02) vẫn PASS và thêm mục kiểm tra `dump_readiness.yaml` hợp lệ.

### 10.2. Thay đổi test cũ

Liệt kê test nào của `check-dump-config`/`evaluate_readiness` phải đổi theo hành vi đúng hơn (L1, L3, L4) và lý do. Không xóa test để cho qua.

### 10.3. Kiểm chứng trên Windows thật (Antigravity ghi lại thành checklist cho người dùng, **không tự giả định kết quả**)

Dùng **máy ảo thử**, không dùng máy sản xuất:
1. Đặt `CrashDumpEnabled = 0` → chạy `dump-readiness`: phải ra `BLOCKED`/`DUMP_DISABLED`.
2. `dump-enable` → registry thành `7`, có đủ 2 tệp sao lưu, nhật ký; trạng thái `READY_PENDING_REBOOT`.
3. Khởi động lại → trạng thái `READY`. Ghi lại: **có cần khởi động lại để có hiệu lực không** (xác nhận hay bác bỏ giả định ở 4.5).
4. Tạo BSOD thử bằng NotMyFault → kiểm tra có file dump mới, volmgr có sự kiện thành công, `proof_level` chuyển sang `evidence_of_success`. Ghi lại **ID và nội dung** các sự kiện volmgr thực tế (đối chiếu 4.4).
5. `dump-rollback` → registry về đúng như ban đầu (thử với cả giá trị vốn không tồn tại).
6. Chạy `Enable-CrashDump.ps1 -WhatIf` rồi chạy thật trên máy ảo thứ hai; thử qua GPO startup nếu có môi trường miền.
7. `dump-fleet` đọc thư mục chia sẻ có ít nhất 3 tệp (một hợp lệ, một hỏng, một cũ).

---

## 11. RỦI RO VÀ BIỆN PHÁP

| Rủi ro | Biện pháp |
|---|---|
| Bật dump làm đầy ổ nhỏ | Ngưỡng dung lượng theo chế độ; không bật khi dưới ngưỡng tối thiểu; chế độ Small chỉ được đề xuất, không tự chọn |
| Hoàn tác sai trạng thái | Sao lưu JSON có "chưa tồn tại"; test hoàn tác với 3 trạng thái ban đầu |
| Người dùng tin "sẵn sàng" nghĩa là chắc chắn có dump | Tách `status` và `proof_level`; thông điệp rõ |
| Gói triển khai lệch logic với phần mềm | P10; test đối chiếu; ưu tiên chế độ `-UseCli` khi có thể |
| Bật hàng loạt sai máy | Hộp thoại liệt kê từng máy; chỉ máy được ma trận cho phép; nhật ký từng máy |
| Báo cáo đội máy cũ/giả | Kiểm tra hợp lệ, đánh dấu cũ, chỉ coi là dữ liệu tham khảo; không tự động hành động dựa trên báo cáo |
| Kênh từ xa bị lạm dụng | Mặc định tắt; không lưu mật khẩu; không tự bật WinRM; giới hạn đồng thời; nhật ký |
| Giả định về Windows sai (khởi động lại, ID volmgr, pagefile) | Đánh dấu `[CẦN XÁC MINH]`, checklist 10.3, cấu hình trong YAML để sửa không cần build lại |

---

## 12. KHÔNG LÀM TRONG ĐỢT NÀY

- Không tự khởi động lại máy, không hẹn giờ khởi động lại.
- Không sửa registry/cấu hình khác ngoài `CrashDumpEnabled` (và `LogEvent` nếu cấu hình cho phép); pagefile chỉ qua chức năng nâng cao mặc định tắt, và chỉ khi xác minh được.
- Không lưu/nhập mật khẩu, không tự bật WinRM hay mở tường lửa, không tự dò mạng.
- Không bật Driver Verifier, không tạo BSOD trên máy thật.
- Không xóa hoặc đụng vào file dump hiện có.
- Không đổi luật chấm điểm (trọng số) hay cách tính độ tin cậy ngoài các điều chỉnh nêu ở 8.1.
- Không thay đổi các bước đóng gói/phát hành ngoài việc bảo đảm `schema.sql` và `dump_readiness.yaml` được đưa vào đúng chỗ.

---

## 13. THỨ TỰ THỰC HIỆN, TIÊU CHÍ HOÀN THÀNH, BÁO CÁO

**Nhánh:** `feature/update-04-dump-readiness`. Mỗi phần (A–E) tối thiểu một commit riêng, message dạng `feat(dump-config): ...` / `fix(dump-config): ...`. Sau mỗi phần chạy `python -m ruff check src` và `python -m pytest -q`.

| Bước | Nội dung | Hoàn thành khi |
|---|---|---|
| 1 | Phần A (4.1–4.6) + sửa L1, L3–L7 | Test ma trận/trạng thái PASS; test cũ đã điều chỉnh có giải thích |
| 2 | Phần B (5.1–5.4) + sửa L2 | Test sao lưu/hoàn tác với 3 trạng thái ban đầu PASS; không có đường nào khởi động lại máy |
| 3 | Phần C (CLI + GUI cục bộ) | Nút khóa/mở đúng; hộp thoại xác nhận bắt buộc; tương thích `check-dump-config` cũ |
| 4 | Phần D 7.1–7.3 (JSON, tổng hợp, gói triển khai) | `dump-fleet` xử lý tệp hỏng/cũ; gói sinh đủ tệp và qua test đối chiếu |
| 5 | Phần E (8.1–8.3) | Event 41 thập phân→hex đúng; `BugcheckCode=0` tách riêng; `dump gap` đúng |
| 6 | Tài liệu, `selftest` bổ sung, CHANGELOG, tăng phiên bản | GitHub Actions xanh (Lint → Pytest → Build → `selftest` trên gói) |
| 7 (tùy chọn) | Phần D 7.4 (từ xa) | Chỉ làm nếu người dùng đồng ý sau bước 6 |

**BÁO CÁO CUỐI (tiếng Việt), theo từng bước:**
1. Đã làm gì (file, hàm, bảng, khóa YAML mới/đổi).
2. Test đã thêm/đổi và kết quả `pytest`/`ruff`; đã xác nhận test fail trước khi sửa với các lỗ hổng L1–L4, L9.
3. **Danh sách `[CẦN XÁC MINH]`** và kết quả kiểm chứng (hoặc "chưa kiểm chứng") theo checklist 10.3.
4. Quyết định đã đưa ra, việc bỏ dở và lý do (đặc biệt 4.3, 5.5, 7.4).
5. Danh sách commit, kết quả GitHub Actions, phiên bản.

---

## PHỤ LỤC A — Mẫu hộp thoại xác nhận (tiếng Việt)

> **Bật ghi dump cho máy PC-KT-05?**
> Hiện trạng: ghi dump đang **tắt** (CrashDumpEnabled = 0).
> Sẽ thay đổi: đặt **CrashDumpEnabled = 7** (Automatic memory dump). Không thay đổi cài đặt nào khác.
> Sao lưu: cấu hình hiện tại sẽ được lưu trước tại `backup\CrashControl_PC-KT-05_<thời gian>.json/.reg`, có thể **Hoàn tác** bất cứ lúc nào.
> ⚠ Cần **khởi động lại máy** để có hiệu lực. Phần mềm **không** tự khởi động lại.
> ⚠ *(nếu có)* Máy vẫn chưa ghi được dump vì: không có pagefile trên ổ C:.
> Thay đổi sẽ được ghi vào nhật ký. [ Hủy ] [ **Bật ghi dump** ]

## PHỤ LỤC B — Khung `Enable-CrashDump.ps1` (tham khảo, phải kiểm thử trên Windows thật)

```powershell
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet(3, 7)] [int]$TargetMode = 7,
    [string]$ReportDir = "",
    [string]$DataDir = "$env:ProgramData\DumpAnalyzer"
)
$ErrorActionPreference = 'Stop'
$keyPs  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$keyReg = 'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Can quyen Administrator.'; exit 3 }

New-Item -ItemType Directory -Force -Path "$DataDir\backup","$DataDir\logs" | Out-Null

# 1) Doc trang thai hien tai: phan biet "khong ton tai" voi "loi doc"
$prop = Get-ItemProperty -Path $keyPs -Name CrashDumpEnabled -ErrorAction SilentlyContinue
$cur  = if ($prop) { [int]$prop.CrashDumpEnabled } else { $null }   # $null = khong ton tai

# 2) Ma tran quyet dinh: chi ghi khi 0 hoac khong ton tai
if ($cur -in 1,2,3,7) { Write-Output "Khong doi: CrashDumpEnabled = $cur"; exit 0 }

# 3) Sao luu .reg + .json (json ghi ro 'present' = false neu khong ton tai)
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = Join-Path "$DataDir\backup" "CrashControl_${env:COMPUTERNAME}_$stamp"
reg export $keyReg "$base.reg" /y | Out-Null
@{ schema_version = 1; hostname = $env:COMPUTERNAME; created_utc = (Get-Date).ToUniversalTime().ToString('o')
   values = @{ CrashDumpEnabled = @{ present = ($null -ne $cur); data = $cur } } } |
    ConvertTo-Json -Depth 5 | Set-Content -Path "$base.json" -Encoding UTF8

# 4) Ghi dung mot gia tri, doc lai de xac nhan
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Dat CrashDumpEnabled = $TargetMode")) {
    Set-ItemProperty -Path $keyPs -Name CrashDumpEnabled -Value $TargetMode -Type DWord
    $after = (Get-ItemProperty -Path $keyPs -Name CrashDumpEnabled).CrashDumpEnabled
    if ($after -ne $TargetMode) { Write-Error 'Doc lai khong khop. Hay hoan tac bang ban sao luu.'; exit 1 }
    Write-Output "Da bat ghi dump. CAN KHOI DONG LAI de co hieu luc (script KHONG tu khoi dong lai)."
}
# 5) (Tuy chon) ghi bao cao JSON theo dac ta 9.2 vao $ReportDir, va nhat ky vao $DataDir\logs
```

## PHỤ LỤC C — Việc người dùng tự kiểm tra sau khi Antigravity xong

1. Làm theo checklist 10.3 trên **máy ảo thử** (bật/tắt dump, khởi động lại, tạo BSOD bằng NotMyFault, hoàn tác).
2. Chạy `DumpAnalyzer-cli.exe dump-readiness` trên 2–3 máy thật (chỉ đọc) và so với System Properties → Advanced → Startup and Recovery.
3. Đặt 3 tệp báo cáo (1 hợp lệ, 1 hỏng, 1 cũ) vào thư mục chia sẻ thử rồi chạy `dump-fleet`.
4. Thử gói triển khai với `-WhatIf` trên một máy, kiểm tra nhật ký; chỉ sau đó mới triển khai thật cho nhóm nhỏ.
5. Gửi lại cho tôi danh sách sự kiện volmgr thực tế (ID và nội dung) và kết quả "có cần khởi động lại không" để tôi hiệu chỉnh ghi chú `[CẦN XÁC MINH]`.
