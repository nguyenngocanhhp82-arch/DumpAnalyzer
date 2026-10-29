# CẬP NHẬT ĐỢT 1 CHO ANTIGRAVITY (sau khi hoàn thành Phase 1)

> File này **bổ sung** cho `ANTIGRAVITY_HANDOFF_DumpAnalyzer.md`.
> Nếu có chỗ mâu thuẫn, **file này ưu tiên**. Phần không nhắc tới thì giữ nguyên như handoff.
> Hãy lưu file này vào repo tại `docs/UPDATE_01.md` và ghi vào `CHANGELOG.md`.

---

## 0. TÓM TẮT CÁC THAY ĐỔI

| # | Thay đổi | Ảnh hưởng tới Phase |
|---|---|---|
| A | Máy **chưa bật ghi dump** vẫn phải phân tích được (chế độ "chỉ log") | Phase 1B (mới), 3, 4, 5 |
| B | Chức năng **Kiểm tra khả năng ghi dump** (chỉ đọc theo mặc định) | Phase 1B (mới) |
| C | Cách lấy mã lỗi từ **Event 41 / 1001** khi không có dump | Phase 3 |
| D | Quy tắc **trần độ tin cậy** mới khi thiếu dump | Phase 4 |
| E | Thông tin giao diện đã chốt (2 màn hình mẫu) | Phase 5 |
| F | Ghi chú **đóng gói .exe** | Phase 6 |
| G | **Quy trình cập nhật sau bàn giao** (Git, CHANGELOG, mẫu báo lỗi) | Mọi Phase |

**Không làm lại Phase 1.** Chỉ thêm phần Phase 1B nhỏ nếu Phase 1 chưa có. Nếu phát hiện thay đổi nào ở đây đòi sửa code Phase 1 đã viết, hãy **liệt kê và hỏi tôi** trước khi sửa.

---

## A. CHẾ ĐỘ "CHỈ LOG" KHI KHÔNG CÓ DUMP

Nhiều máy trong công ty có thể tắt ghi dump, hoặc sập mà không ghi được dump. Công cụ phải xử lý được cả hai trường hợp:

| Tình huống | Cách xử lý |
|---|---|
| Có dump, phân tích được bằng `cdb` | Như handoff |
| Có dump nhưng không có `cdb` | `header_only` (như handoff) |
| **Không có dump nhưng có Event 41/1001 kèm mã Bug Check khác 0** | Tạo bản ghi `crash` loại `none`, `analyzed_by = 'log_only'`, mã lỗi lấy từ event |
| **Không có dump, Event 41 có `BugcheckCode = 0`** | Tạo bản ghi `crash` loại `none`, `analyzed_by = 'log_only'`, nhóm nghi ngờ theo luật `no_dump` (nguồn, nhiệt, treo cứng) |

Yêu cầu:
1. Giao diện và báo cáo phải hiển thị rõ nhãn **"Không có dump – kết luận kém chắc chắn"** và lý do.
2. Khi máy đang tắt ghi dump, kết luận kèm khuyến nghị **bật ghi dump** (xem mục B).
3. Không bao giờ kết luận một **driver cụ thể** là thủ phạm khi chỉ có log. Chỉ được nêu **nhóm thiết bị** (GPU, ổ lưu trữ, RAM, nguồn...). Ngoại lệ: event log tự nêu tên driver (ví dụ nguồn `nvlddmkm`, `stornvme`), khi đó được ghi là "bằng chứng từ log", không phải từ stack.

---

## B. CHỨC NĂNG KIỂM TRA KHẢ NĂNG GHI DUMP (Phase 1B)

### B.1 Lệnh CLI

```bash
dumpanalyzer check-dump-config                 # chỉ ĐỌC, báo kết quả
dumpanalyzer check-dump-config --apply         # bật ghi dump, phải hỏi xác nhận
```

### B.2 Những gì cần kiểm tra (chỉ đọc)

| Mục | Cách lấy | Đánh giá |
|---|---|---|
| Kiểu dump | Registry `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`, giá trị `CrashDumpEnabled` | `0` tắt, `1` complete, `2` kernel, `3` small, `7` automatic |
| Tự khởi động lại sau lỗi | `AutoReboot` | chỉ ghi nhận |
| Ghi đè dump cũ | `Overwrite` | chỉ ghi nhận |
| Thư mục minidump, file dump | `MinidumpDir`, `DumpFile` | chỉ ghi nhận |
| Pagefile | `Get-CimInstance Win32_ComputerSystem` (`AutomaticManagedPagefile`) và `Win32_PageFileUsage` | Cảnh báo nếu không có pagefile trên ổ chứa Windows |
| Dung lượng trống ổ chứa Windows | `Get-PSDrive` hoặc `Win32_LogicalDisk` | Cảnh báo nếu trống ít (ngưỡng cấu hình được, đề xuất mặc định cao hơn RAM nếu chọn kernel/automatic) |
| Lịch sử ghi dump | Event `volmgr` 161 (tạo dump thất bại), 162 (thành công) | Cảnh báo nếu có 161 |

Kết quả mỗi máy: **Sẵn sàng / Cần chú ý / Không ghi được dump**, kèm lý do bằng tiếng Việt.

Lệnh kiểm tra nhanh để đối chiếu khi test:

```bash
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled
```

### B.3 Quy tắc an toàn khi `--apply` (thay đổi cấu hình máy người dùng)

1. **Mặc định chỉ đọc.** Chỉ sửa registry khi có `--apply` **và** người dùng gõ xác nhận.
2. **Sao lưu giá trị cũ** vào file (`backup/CrashControl_<hostname>_<thời gian>.reg` hoặc JSON) trước khi sửa.
3. Chỉ sửa `CrashDumpEnabled` (đặt `7` = Automatic memory dump). **Không đụng** các khoá khác, **không tự tạo hay đổi pagefile**. Nếu thiếu pagefile hoặc thiếu chỗ trống thì chỉ cảnh báo và hướng dẫn.
4. Ghi log mọi thay đổi (máy nào, giá trị cũ, giá trị mới, ai chạy, lúc nào).
5. Báo rõ: "có thể cần khởi động lại máy để áp dụng". Công cụ **không tự khởi động lại máy**.
6. Cần quyền Administrator; thiếu quyền thì dừng và báo.
7. Việc bật dump **từ xa hàng loạt** thuộc Phase 6 (cần WinRM/`Invoke-Command`). Chưa làm ở đợt này, chỉ ghi vào `docs/IDEAS.md`.

Lệnh đặt giá trị (chỉ để Antigravity tham khảo khi viết; công cụ phải thực hiện qua mã Python/`winreg` có sao lưu và xác nhận):

```bash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 7 /f
```

---

## C. LẤY MÃ LỖI TỪ EVENT KHI KHÔNG CÓ DUMP (Phase 3)

| Event | Trường cần đọc |
|---|---|
| `Microsoft-Windows-Kernel-Power` **41** | `BugcheckCode`, `BugcheckParameter1..4` trong `EventData` |
| `Microsoft-Windows-WER-SystemErrorReporting` **1001** | Mã lỗi nằm trong nội dung mô tả sự kiện ("The bugcheck was: 0x...") và có thể kèm đường dẫn dump |
| `EventLog` **6008** | Lần tắt trước không bình thường (chỉ để đối chiếu) |

Lưu ý quan trọng:
1. Trong Event 41, `BugcheckCode` thường là **số thập phân** (ví dụ 278). **Phải đổi sang hex** (0x116) rồi mới tra bảng luật. Có test riêng cho phần này.
2. `BugcheckCode = 0` nghĩa là **không có BSOD**, không phải "mã lỗi 0". Xử lý theo luật `no_dump` (mục A).
3. Event 41 và 1001 của cùng một lần sập có thể cách nhau vài giây đến vài phút (1001 ghi sau khi khởi động lại). Cần **gộp thành một crash**, không đếm hai lần. Quy tắc gộp: cùng máy, chênh lệch thời gian trong khoảng cấu hình được (đề xuất mặc định 10 phút), ưu tiên mã lỗi từ dump nếu có.
4. Khi có dump **và** có event, nếu mã lỗi hai nguồn **khác nhau** thì tin dump, ghi cảnh báo.
5. Dùng cách đọc event bằng XML (`EventData` theo tên trường), không cắt chuỗi mô tả theo vị trí.

Gợi ý lệnh PowerShell để Antigravity tham khảo cách đọc trường theo tên:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} | ForEach-Object {
  $d=@{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
  [pscustomobject]@{Time=$_.TimeCreated; BugcheckCode=$d.BugcheckCode; P1=$d.BugcheckParameter1}
}
```

---

## D. TRẦN ĐỘ TIN CẬY MỚI (Phase 4)

Bổ sung vào mục 6 của handoff (tất cả ngưỡng đặt trong `settings.yaml`):

| Tình huống | Độ tin cậy tối đa |
|---|---|
| Có dump phân tích bằng `cdb` | Như handoff (1 crash tối đa "trung bình") |
| `header_only` | "Trung bình" |
| `log_only` có mã Bug Check khác 0 **và** có event hỗ trợ cùng hướng | "Trung bình" |
| `log_only` có mã Bug Check nhưng không có event hỗ trợ | "Thấp" |
| `log_only` với `BugcheckCode = 0` | "Thấp" |

Quy tắc bổ sung:
1. Kết luận `log_only` chỉ nêu **nhóm thiết bị**, không nêu driver cụ thể (trừ khi event log tự nêu, xem mục A.3).
2. Kết luận `log_only` luôn kèm bước đầu tiên: **bật ghi dump** nếu máy đang tắt (theo kết quả `check-dump-config`), để lần sập sau có dữ liệu.
3. Khi trộn nhiều crash (có dump và không có dump) của cùng một máy, tính điểm bình thường nhưng **crash không có dump có trọng số thấp hơn** (hệ số cấu hình được, đề xuất mặc định 0.5).

---

## E. GIAO DIỆN ĐÃ CHỐT (Phase 5)

Người dùng đã duyệt bản mô phỏng 2 màn hình. Tôi sẽ đính kèm ảnh chụp màn hình trong chat. Nếu không có ảnh, làm theo mô tả sau:

**Khung chung:** thanh tiêu đề "DumpAnalyzer – Phân tích màn hình xanh & khởi động lại"; hàng công cụ gồm Nguồn dữ liệu (Máy này / Thư mục dump đã thu về), Từ, Đến, nút **Phân tích** (nổi bật), nút **Xuất báo cáo**; hàng tab: **Tổng quan | Chi tiết crash | Kết luận | Cài đặt**.

**Tab Tổng quan:** 4 ô thống kê (Số lần sập, Dump đã phân tích x/y, Nghi ngờ chính, Độ tin cậy); bảng các lần sập gồm cột Thời điểm (giờ địa phương), Mã lỗi, Tên lỗi, Module, Nhóm nghi ngờ (nhãn chữ có màu, **không chỉ dựa vào màu**); thanh tiến độ phân tích.

**Tab Kết luận:** cột trái là "Xếp hạng nghi ngờ" (thanh phần trăm kèm số %, nhãn Độ tin cậy) và "Bằng chứng" (có nhãn loại: Dump / Log / Cập nhật / Lưu ý); cột phải là "Việc cần kiểm tra (từ dễ đến khó)" và nút xuất HTML/Excel; ghi chú "kết luận là khoanh vùng xác suất, không phải khẳng định tuyệt đối".

**Bổ sung theo đợt cập nhật này:**
1. Dòng nào là crash `log_only` phải có nhãn **"Không có dump"** trong bảng Tổng quan.
2. Trong tab Cài đặt (hoặc tab riêng) có mục **"Khả năng ghi dump"**: bảng kết quả `check-dump-config` và nút bật ghi dump (có hộp thoại xác nhận, nêu rõ sẽ sửa registry và có thể cần khởi động lại).
3. Chưa thiết kế tab **Chi tiết crash** và **Cài đặt**: làm gọn theo phong cách hai tab trên và **gửi tôi xem bản nháp trước khi hoàn thiện**.
4. Thao tác chạy nền, không làm đơ giao diện; chữ đủ lớn, độ tương phản đủ đọc, nút bấm không quá nhỏ.

---

## F. GHI CHÚ ĐÓNG GÓI .EXE (Phase 6)

1. Dùng PyInstaller dạng **thư mục (`--onedir`)**, không dùng một file (`--onefile`), vì khởi động nhanh hơn và ít bị diệt virus báo nhầm.
2. Thư mục `config/` để **bên cạnh** file `.exe`, không nhúng vào, để người dùng sửa luật mà không cần build lại.
3. Cấu hình `.exe` **tự yêu cầu quyền Administrator** (`--uac-admin`).
4. **Không đóng gói kèm `cdb.exe`.** Máy dùng công cụ cần cài Windows Debugging Tools. Khi thiếu, công cụ báo hướng dẫn cài và vẫn chạy ở chế độ `header_only` / `log_only`. Chưa kiểm tra giấy phép phân phối lại nên không gói chung.
5. Ghi trong `README.md` phần hướng dẫn thêm ngoại lệ diệt virus cho thư mục công cụ, vì file build bằng PyInstaller hay bị báo nhầm.

Lệnh tham khảo (Antigravity tự chỉnh cho đúng dự án):

```bash
pyinstaller --noconfirm --windowed --onedir --name DumpAnalyzer --uac-admin src/dumpanalyzer/gui/main.py
```

---

## G. QUY TRÌNH CẬP NHẬT SAU BÀN GIAO

1. **Dùng Git.** Nếu repo chưa có, khởi tạo ngay. Mỗi Phase hoàn thành thì commit và gắn nhãn phiên bản (ví dụ `v0.1` cho Phase 1). Mỗi đợt cập nhật cũng commit riêng.
2. **Giữ `CHANGELOG.md`** (tiếng Việt): mỗi đợt ghi ngày, phiên bản, thêm gì, sửa gì, ảnh hưởng gì.
3. **Giữ bộ test và dump mẫu.** Trước khi báo hoàn thành bất kỳ việc nào, chạy lại **toàn bộ** test; nếu test cũ hỏng thì sửa hoặc báo, không bỏ qua.
4. **Mỗi lần chỉ làm đúng việc được giao**, không tự sửa chức năng khác. Phát hiện vấn đề khác thì ghi vào `docs/IDEAS.md` rồi hỏi.
5. **Phân loại thay đổi:** thêm luật/driver/mã lỗi chỉ sửa file YAML trong `config/rules/`, không sửa code. Chỉ sửa code khi thêm tính năng hoặc sửa lỗi.
6. Tạo `docs/BUG_REPORT_TEMPLATE.md` với mẫu sau để người dùng báo lỗi:

```text
LỖI / YÊU CẦU CẬP NHẬT
Phiên bản đang dùng: v0.x
Việc tôi làm: ...
Kết quả mong đợi: ...
Kết quả thực tế: ...
File đính kèm: ảnh chụp màn hình, file log (thư mục logs/), file dump liên quan nếu có
Yêu cầu: sửa đúng lỗi này, chạy lại toàn bộ test, cập nhật CHANGELOG.md, không đổi chức năng khác.
```

---

## H. KIỂM TRA PHASE 1 (người dùng làm trước khi sang Phase 2)

Người dùng sẽ kiểm tra tay theo tiêu chí nghiệm thu của Phase 1. Antigravity chuẩn bị sẵn để người dùng làm được dễ dàng:

1. Một lệnh in ra bảng đối chiếu: đường dẫn dump, mã lỗi và 4 tham số do `header_parser` đọc.
2. Hướng dẫn đối chiếu bằng `cdb` trên từng dump:

```bash
cdb.exe -z "C:\dumps\may01.dmp" -c ".bugcheck; q"
```

3. Chạy `scan` lần hai để thấy cache theo SHA256 hoạt động (không phân tích lại file cũ).
4. Nếu mã lỗi hoặc tham số **lệch** so với `cdb`: dừng, báo ngay offset nào, loại dump nào, và **tin `cdb`**.

---

## I. PROMPT GỬI ANTIGRAVITY (dán nguyên khối)

```text
CẬP NHẬT KIẾN THỨC ĐỢT 1 — đây KHÔNG phải yêu cầu làm Phase mới.

BỐI CẢNH
Bạn đã hoàn thành Phase 1 của dự án DumpAnalyzer. Tôi gửi kèm file docs/UPDATE_01.md (file ANTIGRAVITY_UPDATE_01.md) bổ sung cho ANTIGRAVITY_HANDOFF_DumpAnalyzer.md. Nếu mâu thuẫn giữa hai file, UPDATE_01 ưu tiên. Mọi quy tắc và quy trình trong handoff (làm từng Phase, dừng chờ xác nhận, luật nằm trong YAML, kết luận có bằng chứng, trung thực về điều chưa chắc) vẫn áp dụng.

VIỆC CẦN LÀM NGAY (không viết code tính năng mới ở bước này)
1. Đọc kỹ UPDATE_01.md và handoff.
2. Lưu UPDATE_01.md vào docs/UPDATE_01.md, cập nhật docs/ARCHITECTURE.md và CHANGELOG.md (tạo nếu chưa có). Nếu repo chưa có Git, khởi tạo và commit trạng thái Phase 1 hiện tại với nhãn v0.1.
3. Viết cho tôi bản tóm tắt ngắn: bạn hiểu các thay đổi A đến G như thế nào, thay đổi nào ảnh hưởng tới code Phase 1 đã viết (nếu có), và thay đổi nào chỉ ảnh hưởng các Phase sau.
4. Báo cáo Phase 1 theo đúng quy trình: đã làm gì, cách chạy thử bằng lệnh cụ thể, kết quả test, điều chưa chắc chắn, đối chiếu từng tiêu chí nghiệm thu. Chuẩn bị sẵn công cụ đối chiếu theo mục H (bảng mã lỗi đọc từ header, cách đối chiếu bằng cdb).
5. Đề xuất kế hoạch cho Phase 1B (lệnh check-dump-config theo mục B) và nêu rõ file nào sẽ tạo/sửa. Liệt kê câu hỏi còn thiếu.
6. DỪNG và chờ tôi xác nhận. Không code Phase 1B, 2 hay bất kỳ Phase nào khác khi tôi chưa đồng ý.

QUY TẮC AN TOÀN BỔ SUNG
- check-dump-config mặc định CHỈ ĐỌC. Chỉ sửa registry khi có --apply và tôi xác nhận; phải sao lưu giá trị cũ, ghi log thay đổi, chỉ sửa CrashDumpEnabled, không đụng pagefile hay khoá khác, không tự khởi động lại máy.
- Event 41: BugcheckCode thường là số thập phân, phải đổi sang hex trước khi tra luật; BugcheckCode = 0 nghĩa là không có BSOD. Đọc event bằng XML theo tên trường.
- Crash không có dump (log_only) chỉ được kết luận NHÓM thiết bị, không kết luận driver cụ thể (trừ khi event log tự nêu tên driver), và độ tin cậy bị giới hạn theo bảng ở mục D.
- Nếu một thay đổi trong UPDATE_01 đòi sửa code Phase 1 đã viết: liệt kê và hỏi tôi trước, không tự sửa.
- Nếu chưa chắc về một chi tiết kỹ thuật (tên giá trị registry, tên trường event, cú pháp lệnh), nói rõ là chưa chắc và đề xuất cách kiểm chứng. Không đoán rồi trình bày như sự thật.
```

---

## K. TRÌNH TỰ LÀM VIỆC SAU ĐỢT CẬP NHẬT NÀY

1. Antigravity gửi tóm tắt và báo cáo Phase 1 (mục I).
2. Người dùng kiểm tra Phase 1 theo mục H.
3. Nếu đạt: người dùng cho phép làm **Phase 1B**, rồi nghiệm thu.
4. Sau đó mới sang Phase 2 (dùng prompt ngắn của Phase 2 trong handoff).
5. Các mục C, D, E, F áp dụng khi tới Phase tương ứng (3, 4, 5, 6).
