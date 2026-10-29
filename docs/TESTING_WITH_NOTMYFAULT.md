# HƯỚNG DẪN KIỂM THỬ AN TOÀN VỚI SYSINTERNALS NOTMYFAULT

Tài liệu này hướng dẫn kỹ thuật viên IT và kiểm thử viên (QA) cách tạo ra các sự cố màn hình xanh (BSOD) và sập hệ thống có chủ đích trong môi trường kiểm nghiệm an toàn bằng công cụ **NotMyFault** của Microsoft Sysinternals, nhằm kiểm chứng khả năng phân tích và đưa ra kết luận của **DumpAnalyzer**.

---

## 1. NGUYÊN TẮC AN TOÀN BẮT BUỘC

> [!CAUTION]
> **CẢNH BÁO NGUY HIỂM:**
> - **CHỈ THỰC HIỆN TRÊN MÁY ẢO (VMware, VirtualBox, Hyper-V) HOẶC MÁY TÍNH THỬ NGHIỆM RIÊNG.**
> - **TUYỆT ĐỐI KHÔNG CHẠY TRÊN MÁY TÍNH CÔNG VIỆC CHÍNH HOẶC MÁY CHỦ SẢN XUẤT (PRODUCTION SERVER).**
> - Lưu và đóng toàn bộ tài liệu, ứng dụng trước khi bắt đầu bài kiểm tra.

---

## 2. CHUẨN BỊ MÔI TRƯỜNG THỬ NGHIỆM

### Bước 1: Tải NotMyFault chính hãng từ Microsoft
- Truy cập trang chủ Sysinternals: [Microsoft Learn Sysinternals NotMyFault](https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault)
- Tải về và giải nén file `NotMyFault.zip`.
- Thư mục giải nén bao gồm:
  + `NotMyFault.exe` (bản 32-bit)
  + `NotMyFault64.exe` (bản 64-bit — khuyến nghị dùng trên Windows hiện đại)
  + `notmyfaultc.exe` / `notmyfaultc64.exe` (bản dòng lệnh)

### Bước 2: Bật tính năng ghi dump trên máy thử nghiệm
Mở cửa sổ Command Prompt quyền Administrator và chạy lệnh của DumpAnalyzer:
```bash
# Kiểm tra xem máy đã bật ghi dump chưa:
dumpanalyzer check-dump-config

# Nếu CrashDumpEnabled = 0 (đang tắt), kích hoạt ghi dump tự động:
dumpanalyzer check-dump-config --apply
```
*(Khởi động lại máy ảo nếu được yêu cầu để thiết lập registry có hiệu lực).*

---

## 3. CÁC KỊCH BẢN GIẢ LẬP LỖI MÀN HÌNH XANH

Mở file `NotMyFault64.exe` bằng quyền Administrator (`Run as administrator`). Giao diện sẽ hiển thị các loại lỗi kernel driver có thể kích hoạt:

```text
+---------------------------------------------------+
| NotMyFault                                        |
+---------------------------------------------------+
| Crash  Hang  Leak  High IRQL                      |
|                                                   |
| ( ) High IRQL fault (Kernel-mode)                 |
| ( ) Buffer overflow                               |
| ( ) Code overwrite                                |
| ( ) Stack trash                                   |
| ( ) High IRQL fault                               |
|                                                   |
|                [ Crash ]   [ Hang ]               |
+---------------------------------------------------+
```

### Kịch bản 1: Lỗi Driver truy cập bộ nhớ sai cấp độ (High IRQL Fault)
1. Trong tab **Crash**, tích chọn mục **High IRQL fault (Kernel-mode)**.
2. Bấm nút **Crash**.
3. **Hiện tượng:** Máy tính lập tức xuất hiện màn hình xanh BSOD với mã lỗi `0x000000D1: DRIVER_IRQL_NOT_LESS_OR_EQUAL`.
4. Driver gây lỗi: `myfault.sys`.
5. Sau khi máy tự khởi động lại, kiểm tra file dump tại:
   `C:\Windows\Minidump\*.dmp` hoặc `C:\Windows\MEMORY.DMP`.

### Kịch bản 2: Lỗi tràn bộ nhớ đệm Driver (Buffer Overflow)
1. Trong NotMyFault, chọn mục **Buffer overflow**.
2. Bấm nút **Crash**.
3. **Hiện tượng:** Màn hình xanh BSOD xuất hiện với mã `0x000000F7: DRIVER_OVERRUN_STACK_BUFFER`.

### Kịch bản 3: Lỗi ghi đè vùng nhớ chỉ đọc (Code Overwrite)
1. Chọn mục **Code overwrite**.
2. Bấm nút **Crash**.
3. **Hiện tượng:** Màn hình xanh xuất hiện với mã `0x000000BE: ATTEMPTED_WRITE_TO_READONLY_MEMORY`.

### Kịch bản 4: Giả lập sập nguồn đột ngột không kịp tạo dump (Event 41, BugcheckCode = 0)
1. Trong máy ảo (Virtual Machine), chọn thao tác **Reset** hoặc **Power Off** đột ngột (tương tự như rút phích cắm điện máy thật).
2. Bật lại máy ảo.
3. Windows sẽ ghi nhận sự kiện `Kernel-Power 41` với `BugcheckCode = 0` trong Windows Event Log (không có file `.dmp`).

---

## 4. ĐỐI CHIẾU KẾT QUẢ VỚI DUMPANALYZER

Sau khi máy khởi động lại thành công, mở DumpAnalyzer để kiểm tra:

### Cách 1: Kiểm tra bằng giao diện đồ họa (GUI)
1. Mở `DumpAnalyzer.exe` (hoặc chạy `python src/dumpanalyzer/gui/main.py`).
2. Chọn nguồn dữ liệu: **"Máy này"** (hoặc chọn thư mục dump đã copy về).
3. Bấm **Phân tích**.
4. **Kiểm tra kết quả tab Tổng quan:**
   - Số lần sập tăng lên tương ứng.
   - Mã lỗi hiển thị chính xác: `0xD1`, `0xF7` hoặc `0xBE`.
   - Cột Module nhận diện đúng driver: `myfault.sys`.
5. **Kiểm tra kết quả tab Kết luận:**
   - Xếp hạng nghi ngờ: Nhóm **Driver bên thứ ba** đứng đầu với tỷ lệ cao (> 85%).
   - Bằng chứng củng cố: Hiển thị liên kết giữa stack trace file dump và sự kiện Event 41/1001.

### Cách 2: Kiểm tra bằng dòng lệnh CLI
```bash
# Quét thu thập dump mới:
dumpanalyzer scan

# Quét tích hợp Windows Event Log:
dumpanalyzer events

# Xuất phán quyết chẩn đoán:
dumpanalyzer verdict
```

### Cách 3: Đối chiếu với WinDbg (chuẩn tham chiếu Microsoft)
Nếu máy có cài đặt WinDbg (`cdb.exe`), chạy lệnh sau để so khớp:
```cmd
cdb.exe -z "C:\Windows\Minidump\<tên_file>.dmp" -c ".bugcheck; lmvm myfault; q"
```
Kết quả của DumpAnalyzer phải trùng khớp 100% về mã Bug Check, 4 tham số ngoại lệ và module gây lỗi so với WinDbg.
