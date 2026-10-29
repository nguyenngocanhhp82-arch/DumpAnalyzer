# HƯỚNG DẪN KIỂM THỬ DUMPANALYZER VỚI NOTMYFAULT (TESTING_WITH_NOTMYFAULT)

Tài liệu này hướng dẫn kỹ thuật viên IT cách tạo dump màn hình xanh (BSOD) thực tế trên máy ảo bằng công cụ chính thức của Microsoft (**Sysinternals NotMyFault**) để kiểm chứng độ chính xác và tính năng của **DumpAnalyzer**.

---

## 1. YÊU CẦU MÔI TRƯỜNG THỰC NGHIỆM

> [!CAUTION]
> **TUYỆT ĐỐI KHÔNG CHẠY NOTMYFAULT TRÊN MÁY TÍNH LÀM VIỆC CHÍNH HOẶC MÁY CHỦ PRODUCTIVE!**
> NotMyFault sẽ chủ động làm sập nhân Windows (Kernel Crash) ngay lập tức. Mọi dữ liệu chưa lưu sẽ bị mất.

### Khuyến nghị:
- Sử dụng máy ảo: **VMware Workstation**, **Hyper-V** hoặc **VirtualBox**.
- Hệ điều hành máy ảo: Windows 10 hoặc Windows 11 (bản 64-bit).
- Bộ nhớ RAM máy ảo: 4 GB – 8 GB.
- Dung lượng ổ C: Còn trống tối thiểu 20 GB.

---

## 2. CHUẨN BỊ MÁY ẢO TRƯỚC KHI TẠO CRASH

### Bước 2.1: Bật chế độ ghi Dump tự động
Trên máy ảo, mở Command Prompt với quyền **Run as administrator** và chạy:
```cmd
DumpAnalyzer-cli.exe apply-dump-config
```
Lệnh này sẽ:
1. Tự động sao lưu registry hiện tại ra file `.reg`.
2. Bật chế độ **Automatic Memory Dump** (`CrashDumpEnabled = 7`).
3. Đảm bảo file pagefile trên ổ C có dung lượng đủ lớn để lưu trữ dump.

### Bước 2.2: Tải công cụ NotMyFault
1. Truy cập trang chính thức của Microsoft Sysinternals:
   [https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault](https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault)
2. Tải về và giải nén file `NotMyFault.zip`.
3. Thư mục giải nén sẽ chứa `NotMyFault.exe` (bản 32-bit) và `NotMyFault64.exe` (bản 64-bit).

---

## 3. CÁC KỊCH BẢN TẠO CRASH ĐIỂN HÌNH

Khởi chạy `NotMyFault64.exe` với quyền **Administrator**. Chọn một trong các kịch bản sau:

### Kịch bản 1: Lỗi truy cập vùng nhớ mức ưu tiên cao (High IRQL Fault)
- **Thiết lập trong NotMyFault**:
  - Chọn tab: **BSOD**
  - Radio button: **High IRQL fault (Kernel-mode)**
  - Nhấn nút: **Crash**
- **Kết quả BSOD**:
  - Mã Bug Check: `0x000000D1` (`DRIVER_IRQL_NOT_LESS_OR_EQUAL`)
  - Driver gây lỗi hiển thị trên màn hình xanh: `myfault.sys`

---

### Kịch bản 2: Tràn bộ đệm nhân Kernel (Buffer Overrun)
- **Thiết lập trong NotMyFault**:
  - Chọn tab: **BSOD**
  - Radio button: **Buffer overflow**
  - Nhấn nút: **Crash**
- **Kết quả BSOD**:
  - Mã Bug Check: `0x00000139` (`KERNEL_SECURITY_CHECK_FAILURE`)
  - Thủ phạm: `myfault.sys`

---

### Kịch bản 3: Hỏng cấu trúc bộ nhớ cấp phát (Corrupt Pool)
- **Thiết lập trong NotMyFault**:
  - Chọn tab: **BSOD**
  - Radio button: **Pool corruption**
  - Nhấn nút: **Crash**
- **Kết quả BSOD**:
  - Mã Bug Check: `0x000000C2` (`BAD_POOL_CALLER`)

---

### Kịch bản 4: Treo DPC / Treo hệ thống (Hang)
- **Thiết lập trong NotMyFault**:
  - Chọn tab: **Hang**
  - Chọn loại hang và nhấn nút: **Hang**
- **Kết quả BSOD**:
  - Hệ thống sẽ bị treo và sau đó kích hoạt `0x00000133` (`DPC_WATCHDOG_VIOLATION`).

---

## 4. KIỂM CHỨNG KẾT QUẢ VỚI DUMPANALYZER

Sau khi máy ảo tự khởi động lại và đăng nhập vào Windows:

### Cách 1: Sử dụng giao diện đồ họa (GUI)
1. Mở `DumpAnalyzer.exe` hoặc click đúp `run_gui.bat`.
2. Nguồn phân tích mặc định là: **Máy cục bộ này**.
3. Bấm nút **"⚡ Phân tích ngay"**.
4. Kiểm tra các kết quả hiển thị trên 3 tab chính:
   - **Tab Tổng quan**: Thấy vụ sập mới nhất với mã `0xD1` hoặc `0x139`.
   - **Tab Chi tiết crash**:
     - `IMAGE_NAME` và `MODULE_NAME` hiển thị chính xác là `myfault.sys`.
     - Monospace `STACK_TEXT` hiển thị rõ đỉnh stack gọi vào `myfault!myfault_ioctl`.
   - **Tab Kết luận**:
     - Nghi ngờ chính: `Driver (myfault.sys)`.
     - Độ tin cậy: **Trung bình** (với 1 dump) hoặc **Cao** (nếu tạo 2 lần cùng crash).
     - Rationale tiếng Việt giải thích rõ driver `myfault.sys` xuất hiện trực tiếp tại đỉnh stack.
     - Các bước khuyến nghị từ dễ đến khó (gỡ driver, cập nhật, rollback).

### Cách 2: Sử dụng dòng lệnh (CLI)
Mở PowerShell hoặc Command Prompt trong thư mục DumpAnalyzer và chạy:
```cmd
DumpAnalyzer-cli.exe scan
```
Sau đó phân tích sâu:
```cmd
DumpAnalyzer-cli.exe analyze --all
```
Xem kết luận chẩn đoán:
```cmd
DumpAnalyzer-cli.exe verdict --latest
```

---

## 5. ĐỐI CHIẾU VỚI WINDBG PREVIEW (MICROSOFT)

Để đảm bảo tính trung thực và khách quan tuyệt đối:
1. Mở công cụ **WinDbg Preview** (tải miễn phí từ Microsoft Store).
2. Vào **File** -> **Open dump file** -> chọn file `C:\Windows\Minidump\xxxx.dmp`.
3. Gõ lệnh: `!analyze -v`
4. Đối chiếu các trường sau giữa WinDbg và DumpAnalyzer:
   - `BUGCHECK_CODE`: Khớp 100%.
   - `IMAGE_NAME`: Khớp 100% (`myfault.sys`).
   - `FAILURE_BUCKET_ID`: Khớp 100%.
   - `PROCESS_NAME`: Khớp 100% (`NotMyFault64.exe`).

Nếu tất cả các chỉ số trên khớp hoàn toàn, bộ cài **DumpAnalyzer** đã đạt tiêu chuẩn nghiệm thu và sẵn sàng triển khai thực tế trên toàn bộ hệ thống máy tính công ty!
