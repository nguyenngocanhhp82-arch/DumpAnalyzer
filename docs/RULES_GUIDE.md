# HƯỚNG DẪN TÙY BIẾN VÀ BỔ SUNG BỘ LUẬT CHẨN ĐOÁN (RULES_GUIDE)

Tài liệu này dành riêng cho nhân viên IT / Kỹ thuật viên hệ thống muốn mở rộng, thêm bớt hoặc điều chỉnh các quy tắc chẩn đoán lỗi màn hình xanh (BSOD) và sự cố máy tính trong **DumpAnalyzer**.

Mọi luật chẩn đoán được lưu trữ dưới định dạng **YAML** trong thư mục:
```text
config/rules/
├── bugcheck_rules.yaml    # Trọng số nghi ngờ và khuyến nghị cho từng mã lỗi BSOD
├── driver_map.yaml        # Phân loại driver phần cứng (GPU, SSD, RAM, mạng...)
├── event_rules.yaml       # Quy tắc cộng/trừ điểm theo sự kiện Windows Event Log
└── patterns.yaml          # Mẫu hình nhận diện khi máy bị sập nhiều lần
```

---

## 1. NGUYÊN TẮC CƠ BẢN VỀ ĐỊNH DẠNG YAML

1. **Thụt lề bằng khoảng trắng (Space)**: Tuyệt đối **KHÔNG dùng phím Tab**. Khuyến nghị thụt lề 2 dấu cách cho mỗi cấp độ.
2. **Cặp khóa - giá trị**: Luôn có dấu hai chấm và một khoảng trắng `khoa: gia_tri`.
3. **Mã Hex**: Có thể viết dạng chuỗi `0x124` hoặc `124` (DumpAnalyzer tự động chuẩn hóa về chữ hoa `0x124`).
4. **Kiểm tra sau khi sửa**: Luôn chạy lệnh kiểm tra cú pháp trước khi sử dụng:
   ```bash
   DumpAnalyzer-cli.exe validate-rules
   ```
   Hoặc bấm nút **"Kiểm tra luật YAML"** trong tab **Cài đặt** trên giao diện đồ họa.

---

## 2. HƯỚNG DẪN CHỈNH SỬA TỪNG FILE LUẬT

### 2.1. `bugcheck_rules.yaml` — Bổ sung mã lỗi Bug Check mới

Mỗi mã lỗi quy định trọng số nghi ngờ ban đầu (prior) cho từng nhóm linh kiện và danh sách các bước khắc phục đề xuất theo thứ tự từ dễ đến khó.

#### Cấu trúc mẫu:
```yaml
0x116:
  name: "VIDEO_TDR_FAILURE"
  suspects:
    gpu: 65         # Nghi vấn card đồ hoạ / driver màn hình
    thermal: 20     # Quá nhiệt GPU
    driver: 15      # Xung đột driver
  extra_cdb:
    - "!dpx"        # Lệnh cdb bổ sung khi phân tích sâu
  next_steps:
    - "Dùng phần mềm DDU (Display Driver Uninstaller) gỡ sạch driver card màn hình trong Safe Mode"
    - "Cài đặt lại bản driver GPU WHQL ổn định nhất từ trang chủ NVIDIA/AMD/Intel"
    - "Kiểm tra nhiệt độ GPU và vệ sinh quạt tản nhiệt của card đồ hoạ"
    - "Thử giảm xung nhịp (underclock) hoặc thay thế card đồ hoạ sang máy khác để kiểm tra"
```

#### Các nhóm nghi vấn (`suspects`) hợp lệ:
- `cpu`: Vi xử lý, điện áp VCore, nhiệt độ CPU.
- `ram`: Bộ nhớ trong, xung RAM, timing XMP.
- `gpu`: Card đồ hoạ, driver màn hình, bộ nhớ VRAM.
- `storage`: Ổ cứng SSD, HDD, cáp SATA, controller NVMe.
- `psu`: Bộ nguồn máy tính, sụt áp 12V/5V.
- `thermal`: Quá nhiệt chung của linh kiện hoặc thùng máy.
- `driver`: Driver phần mềm bên thứ ba.
- `system`: Tiến trình hoặc service hệ thống Windows.

---

### 2.2. `driver_map.yaml` — Phân loại Driver và Thiết bị phần cứng

File này giúp DumpAnalyzer nhận diện driver gặp sự cố (`IMAGE_NAME` hoặc module trên stack) thuộc về thiết bị nào, từ đó quy trách nhiệm chính xác thay vì đổ lỗi cho Windows.

#### Cấu trúc mẫu:
```yaml
# 1. Driver card đồ hoạ (GPU)
nvlddmkm.sys:
  device: "Card đồ hoạ NVIDIA GeForce / Quadro"
  type: "gpu"
  action: "Gỡ sạch driver bằng DDU và cài đặt bản driver WHQL mới nhất từ nvidia.com"

amdkmdag.sys:
  device: "Card đồ hoạ AMD Radeon"
  type: "gpu"
  action: "Dùng AMD Cleanup Utility và cài lại driver từ amd.com"

# 2. Driver lưu trữ và Controller SSD
stornvme.sys:
  device: "SSD NVMe Controller"
  type: "storage"
  action: "Kiểm tra sức khoẻ ổ cứng bằng CrystalDiskInfo (SMART) và cập nhật firmware SSD"

# 3. Driver mạng
rt640x64.sys:
  device: "Card mạng LAN Realtek Gigabit"
  type: "network"
  action: "Cập nhật driver card mạng từ trang chủ bo mạch chủ hoặc Realtek"

# 4. Danh sách module lõi Microsoft: LUÔN LÀ NẠN NHÂN, KHÔNG ĐỔ LỖI
ms_core_modules:
  - ntoskrnl.exe
  - ntkrnlmp.exe
  - win32k.sys
  - win32kfull.sys
  - fltmgr.sys
```

> **Lưu ý quan trọng**: Nếu `IMAGE_NAME` trong dump là `ntoskrnl.exe`, DumpAnalyzer sẽ **tự động hạ điểm đổ lỗi** cho hệ điều hành và truy quét call stack để tìm driver bên thứ ba thực sự gây lỗi!

---

### 2.3. `event_rules.yaml` — Bổ sung quy tắc từ Windows Event Log

Quy định điểm số cộng thêm vào giả thuyết khi phát hiện các Event ID cụ thể trong vòng 10 phút trước khi máy sập.

#### Cấu trúc mẫu:
```yaml
- source: "disk"
  ids: [7, 11, 15]
  description: "Phát hiện khối nhớ ổ đĩa bị lỗi (Bad block / Controller error)"
  adds:
    storage: 35
  next_steps:
    - "Sao lưu dữ liệu gấp và kiểm tra thông số SMART ổ cứng"
    - "Thay thế cáp tín hiệu SATA hoặc kiểm tra khe cắm M.2"

- source: "Microsoft-Windows-WHEA-Logger"
  ids: [18, 19, 47]
  description: "Lỗi phần cứng phần cứng nghiêm trọng do WHEA ghi nhận"
  adds:
    cpu: 30
    ram: 25
  cap:
    cpu: 60       # Trần điểm tối đa của quy tắc này cho CPU
    ram: 50       # Trần điểm tối đa của quy tắc này cho RAM
  next_steps:
    - "Tắt chế độ ép xung CPU/RAM (XMP) trong BIOS"
    - "Kiểm tra nhiệt độ CPU khi chịu tải nặng"
```

#### Ý nghĩa của trường `cap` (Giới hạn điểm tối đa):
- Khi một sự kiện (ví dụ WHEA hoặc Disk error) xảy ra liên tục hàng chục, hàng trăm lần trong cửa sổ tương quan, nếu chỉ cộng dồn `adds * số lần` thì điểm số sẽ bị thổi phồng vượt mức thực tế.
- Khóa `cap` đặt mức trần điểm số tối đa mà quy tắc đó có thể đóng góp cho từng đối tượng nghi vấn trong một vụ sập:
  $$\text{Điểm quy tắc cho suspect} = \min(\text{số sự kiện} \times \text{adds}[suspect], \text{cap}[suspect])$$

#### Thứ tự tính toán điểm số (Scoring Order):
1. **Điểm Bug Check khởi điểm (`bugcheck_rules.yaml`)**: Xác định các nhóm nghi vấn ban đầu dựa theo mã sập.
2. **Điểm Driver trong Call Stack (`driver_map.yaml`)**: Phân định nạn nhân (module hệ điều hành Microsoft) và thủ phạm (driver bên thứ ba).
3. **Điểm Event Log (`event_rules.yaml`)**: Cộng điểm từ các sự kiện xảy ra gần thời điểm sập, áp dụng `cap` cho từng quy tắc.
4. **Chuẩn hoá điểm**: Chuyển đổi tổng điểm thô về tỷ lệ phần trăm (0 - 100%).
5. **Áp dụng trần độ tin cậy (Confidence Caps)**:
   - 1 crash đơn lẻ: tối đa "trung bình".
   - header_only (không có CDB stack trace): tối đa "trung bình".
   - log_only mã 0: tối đa "thấp".
6. **Nhận diện xu hướng (`patterns.yaml`)**: Thưởng điểm lặp lại khi phân tích trên nhiều lần sập của cùng một máy tính.


---

### 2.4. `patterns.yaml` — Mẫu hình nhận diện khi máy bị sập nhiều lần

Khi một máy tính gặp từ 2 vụ sập trở lên, file này giúp phát hiện các mẫu hình nâng cao.

#### Các mẫu hình tiêu biểu:
1. **Lặp lại cùng một driver bên thứ ba**:
   ```yaml
   - name: "repeat_same_driver"
     condition: "repeat_third_party_module >= 2"
     description: "Cùng một driver bên thứ ba xuất hiện liên tiếp trong nhiều lần sập"
     add:
       driver_of_module: 40
     next_steps:
       - "Driver này là thủ phạm chính, hãy gỡ bỏ hoặc quay về phiên bản cũ (Rollback)"
   ```

2. **Nhiều mã lỗi khác nhau nhưng toàn module hệ thống (Nghi ngờ phần cứng RAM/CPU)**:
   ```yaml
   - name: "random_ms_modules_hardware_flaky"
     condition: "all_ms_modules and diff_bugchecks >= 2"
     description: "Các lần sập có mã lỗi khác nhau và chỉ dừng tại module Windows (dấu hiệu RAM/Nguồn chập chờn)"
     add:
       ram: 30
       psu: 20
     next_steps:
       - "Chạy MemTest86 ít nhất 2 lượt (pass) để kiểm tra từng thanh RAM"
       - "Kiểm tra điện áp cấp từ bộ nguồn (PSU)"
   ```

---

### 2.5. Các trường mới cho Bằng chứng: `strength`, `group_id`, `polarity`, `cap` (Đợt 03)

Từ phiên bản v1.1.0, mỗi luật trong `event_rules.yaml`, `system_rules.yaml`, `patterns.yaml` hỗ trợ các trường nâng cao:
- **`strength`** (`strong` | `medium` | `weak`):
  - `strong`: Bằng chứng mang tính xác quyết cao (ví dụ WHEA Event 18, SMART ổ đĩa báo hỏng, test phần cứng failed, driver lặp lại nhiều dump).
  - `medium`: Bằng chứng gián tiếp hoặc hỗ trợ (TDR màn hình, sập ngẫu nhiên nhiều ứng dụng, sự cố đội máy).
  - `weak`: Gợi ý yếu, một dump đơn lẻ, cờ ép xung RAM, mã BugCheck đơn lẻ.
- **`group_id`**: Định danh nhóm nguồn gốc độc lập (ví dụ `whea_error`, `disk_io_failure`, `fleet_cross_machine`).
  - Để đạt độ tin cậy **CAO**, hệ thống yêu cầu tối thiểu 2 bằng chứng `strong` từ **2 `group_id` khác nhau**.
- **`polarity`** (`support` | `refute`, mặc định `support`):
  - `support`: Ủng hộ kết luận, cộng điểm nghi ngờ.
  - `refute`: Phản bác kết luận, trừ điểm nghi ngờ (sàn 0.0) và ngăn chặn nhãn "CAO" nếu là phản bác mạnh.
- **`cap`**: Điểm trần tối đa mà một sự kiện hoặc nhóm quy tắc có thể đóng góp, ngăn chặn sự kiện lặp lại làm méo mó xác suất.

---

### 2.6. `system_rules.yaml` — Ngưỡng phần cứng & Phân tích Đội máy
Nằm tại `config/rules/system_rules.yaml`, quy định:
- Ngưỡng phần cứng Sysinfo:
  - `storage.wear_critical`: Tỷ lệ hao mòn đĩa (mặc định 90%).
  - `bios.old_years_threshold`: Tuổi BIOS cũ hơn N năm (mặc định 3).
  - `gpu_driver.old_months_threshold`: Driver card màn hình cũ hơn N tháng (mặc định 12).
- Phân tích Đội máy (`fleet_rules`):
  - `min_machines`: Số lượng máy tối thiểu xuất hiện cùng lỗi để xem là sự cố diện rộng (mặc định 3).
  - `window_days`: Cửa sổ thời gian gom sự cố toàn đội máy (mặc định 30 ngày).

---

### 2.7. `test_rules.yaml` — Quy tắc Kiểm tra Phần cứng
Nằm tại `config/rules/test_rules.yaml`, định nghĩa:
- **`evidence_conversion`**: Quy đổi kết quả kiểm tra phần cứng (`failed`, `passed`) thành Bằng chứng `Evidence`.
  - Lỗi RAM `passed` sinh `weak refute` vì lỗi RAM thường chập chờn.
  - Kiểm tra ổ đĩa `passed` sinh `medium refute`.
- **`memory_diagnostic_event_map`**: Ánh xạ Event ID từ provider `Microsoft-Windows-MemoryDiagnostics-Results` sang trạng thái (`1101/1201` -> passed, `1102/1202` -> failed). Nếu gặp Event ID lạ chưa có trong bảng, hệ thống gán trạng thái `inconclusive`.
- **`external_test_rules`**: Quy định số lượt chạy tối thiểu (`min_passes`, mặc định 4) cho MemTest86/OCCT để được xem là đạt.

---

### 2.8. `next_steps.yaml` & `confidence_policy` — Gợi ý Bước Tiếp Theo & Độ Tin Cậy
- `next_steps.yaml`:
  - `suspect_steps`: Danh sách hành động khuyến nghị cho từng nhóm (`ram`, `storage`, `gpu`, `cpu`, `driver`, `psu`, `thermal`, `software`).
  - `missing_data_hints`: Tự động nhận diện dữ liệu còn thiếu (chưa có WinDbg/cdb, dump loại minidump, chỉ có 1 crash, chưa chạy test phần cứng tương ứng) và xuất gợi ý khắc phục.
- `confidence_policy` (trong `settings.yaml`):
  - `high_min_strong_evidence`: Tối thiểu 2 bằng chứng strong từ >= 2 `group_id` độc lập để đạt mức "CAO".
  - `medium_min_strong`: 1 bằng chứng strong hoặc >= 2 medium để đạt mức "TRUNG BÌNH".
  - Các trường hợp khác đánh giá mức "THẤP".

---

### 2.9. `dump_readiness.yaml` — Quy tắc & Ngưỡng Sẵn sàng Ghi Dump (Đợt 04)
Nằm tại `config/rules/dump_readiness.yaml`, quy định toàn diện các tham số chẩn đoán và triển khai an toàn:
- `modes`: Mô tả và phân loại các chế độ ghi dump của Windows (0: Tắt, 1: Complete, 2: Kernel, 3: Small/Minidump, 7: Automatic).
- `disk_thresholds`: Ngưỡng dung lượng trống ổ đĩa tối thiểu cho từng chế độ:
  - `mode_7` (Automatic): Khuyến nghị RAM + 5 GB, tối thiểu 10 GB.
  - `mode_3` (Small dump): Tối thiểu 2.0 GB.
- `volmgr_rules`: Thời gian quét sự kiện volmgr (`lookback_days: 180`), danh sách mã lỗi (`161, 45, 46, 49`) và mã thành công (`162`).
- `dump_gap_rules`: Cửa sổ đối chiếu giữa Kernel-Power Event 41 và file dump (`lookback_days: 90`, `match_window_minutes: 15`).
- `fleet_rules`: Ngưỡng đánh dấu báo cáo đội máy cũ (`stale_days: 14`), số lượng máy xử lý song song (`remote_max_parallel: 5`).
- `reason_codes`: Bảng mã lý do chuẩn hóa (`DUMP_DISABLED`, `DUMP_VALUE_MISSING`, `REGISTRY_UNREADABLE`, `DUMP_MODE_SMALL`, `PAGEFILE_MISSING`, `PAGEFILE_UNKNOWN`, `DISK_LOW`, `VOLMGR_FAILURE_RECENT`, `DUMP_FILES_MISSING`, `PENDING_REBOOT`, `NOT_ADMIN`).

### 2.10. `event_categories.yaml` — Phân Loại Nghiệp Vụ Windows Event Log (Đợt 06)
Tệp `config/rules/event_categories.yaml` phân chia các sự kiện vào 8 nhóm nghiệp vụ IT chuẩn hóa:
1. `crash_reboot`: Sập & Khởi động bất thường (Event 41, 6008, WER/BugCheck 1001, User32 1074, Kernel-General 12, EventLog 6005/6006).
2. `hardware`: Lỗi kiến trúc phần cứng qua WHEA-Logger (IDs: 1, 17, 18, 19, 20, 47).
3. `storage`: Lưu trữ & Hệ thống tệp (Disk 7/11/51/153, stornvme 129, storahci 129, Ntfs 55, volmgr 161/162).
4. `usb_device`: USB & Thiết bị ngoại vi (Kernel-PnP 219, CodeIntegrity 3033/3063, USBSTOR).
5. `display_gpu`: Màn hình & Card đồ họa (Display 4101 TDR, nvlddmkm 13/14, amdkmdag, igfx).
6. `updates_install`: Cập nhật & Cài đặt phần mềm (WindowsUpdateClient 19/20, MsiInstaller 11707/1033).
7. `app_service`: Dịch vụ & Ứng dụng (Application Error 1000, Service Control Manager).
8. `power_thermal`: Nguồn & Nhiệt độ (Kernel-Processor-Power 37).

> [!NOTE]
> Các ID chưa được kiểm chứng trên Windows thật được đánh dấu `[CẦN XÁC MINH]`. Kỹ thuật viên IT có thể tự do bổ sung các Provider và ID riêng của công ty mà không cần sửa code.

---

## 3. THAO TÁC KIỂM TRA TỰ ĐỘNG (VALIDATE RULES)

Sau khi chỉnh sửa bất kỳ file YAML nào:
1. Mở cửa sổ dòng lệnh và chạy:
   ```bash
   DumpAnalyzer-cli.exe validate-rules
   ```
2. Nếu có lỗi thụt lề hoặc sai kiểu dữ liệu, phần mềm sẽ chỉ rõ:
   - Tên file bị lỗi.
   - Số dòng và cột bị lỗi chính xác.
   - Nội dung chi tiết cần sửa.
3. Khi màn hình thông báo:
   ```text
   [OK] Tất cả các file cấu hình và luật chẩn đoán đều hợp lệ!
   ```
   Bạn đã sẵn sàng sử dụng bộ luật mới!
