# HƯỚNG DẪN QUẢN TRỊ & TÙY BIẾN QUY TẮC CHẨN ĐOÁN (RULES GUIDE)

Tài liệu này dành cho **Kỹ thuật viên IT, Quản trị viên hệ thống (Sysadmin) và Kỹ sư bảo trì** nhằm giúp dễ dàng tùy biến, mở rộng và cập nhật các luật chẩn đoán của phần mềm **DumpAnalyzer** mà **không cần chỉnh sửa mã nguồn Python** hay biên dịch lại phần mềm.

---

## 1. TỔNG QUAN HỆ THỐNG QUY TẮC

Toàn bộ tri thức chẩn đoán của DumpAnalyzer được lưu trữ dưới định dạng **YAML** thuần túy trong thư mục:
```text
DumpAnalyzer/
└── config/
    ├── settings.yaml          # Ngưỡng điểm, trọng số, đường dẫn mặc định
    ├── data/
    │   └── bugcheck_codes.json # 380 mã Bug Check chuẩn của Microsoft
    └── rules/
        ├── bugcheck_rules.yaml # Quy tắc phân loại và xử lý từng mã lỗi màn hình xanh
        ├── driver_map.yaml     # Bảng ánh xạ tên file driver (.sys) sang linh kiện
        ├── event_rules.yaml    # Quy tắc chấm điểm sự kiện Windows Event Log
        └── patterns.yaml       # Mẫu hình kết hợp khi máy tính sập nhiều lần
```

> [!TIP]
> Khi sử dụng bản đóng gói `.exe`, thư mục `config/` nằm ngay **bên cạnh file DumpAnalyzer.exe**. Bạn chỉ cần mở file bằng Notepad hoặc VS Code để sửa, lưu lại là phần mềm sẽ tự động áp dụng trong lần phân tích tiếp theo!

---

## 2. HƯỚNG DẪN THÊM MÃ BUG CHECK MỚI (`bugcheck_rules.yaml`)

Mỗi khi Microsoft ra mắt mã lỗi mới hoặc bạn muốn tinh chỉnh cách xử lý một mã lỗi cụ thể, hãy mở file `config/rules/bugcheck_rules.yaml`.

### Cấu trúc một quy tắc Bug Check:
```yaml
bugchecks:
  "0x154":                              # Mã lỗi dạng Hex viết hoa (bắt buộc)
    name: "UNEXPECTED_STORE_EXCEPTION"   # Tên chuẩn của mã lỗi
    description: "Lỗi bất thường trong hệ thống bộ nhớ đệm hoặc ổ đĩa chứa paging store."
    suspects:                           # Phân bổ tỷ lệ nghi ngờ ban đầu (%)
      storage: 60                       # Nhóm nghi ngờ: điểm trọng số (0 - 100)
      ram: 25
      driver: 15
    next_steps:                         # Các bước khuyến nghị IT (tự động xếp DỄ -> KHÓ)
      - "Kiểm tra sức khoẻ ổ đĩa bằng CrystalDiskInfo (chỉ số SMART)"
      - "Chạy lệnh 'chkdsk C: /f /r' trong Command Prompt quyền Administrator"
      - "Cập nhật driver controller ổ cứng (Intel RST, AMD RAID hoặc NVMe driver)"
      - "Chạy MemTest86 kiểm tra RAM"
```

### Các nhóm nghi ngờ hợp lệ (`suspects`):
| Nhóm (`suspect`) | Tên tiếng Việt hiển thị | Ý nghĩa |
|---|---|---|
| `driver` | Driver bên thứ ba | Xung đột driver phần cứng, phần mềm diệt virus |
| `ram` | Bộ nhớ RAM | Lỗi ô nhớ, tiếp xúc chân RAM, sai XMP/DOCP |
| `storage` | Ổ cứng / Lưu trữ | Ổ SSD/HDD lỗi bad sector, lỗi cáp, controller |
| `gpu` | Card đồ họa / Màn hình | Driver GPU crash, quá nhiệt GPU, hỏng VRAM |
| `psu` | Bộ nguồn (PSU) | Nguồn sụt áp khi tải nặng, tụ nguồn lão hoá |
| `thermal` | Nhiệt độ / Quá nhiệt | Quạt khô dầu, keo tản nhiệt thoái hoá |
| `cpu` | Vi xử lý (CPU) | Lỗi tập lệnh, ép xung (overclock) không ổn định |
| `motherboard` | Bo mạch chủ | Lỗi VRM, chipset, BIOS lỗi thời |
| `windows_update` | Bản cập nhật Windows | Xung đột sau khi cài bản vá KB |

---

## 3. HƯỚNG DẪN ÁNH XẠ DRIVER MỚI (`driver_map.yaml`)

Khi một driver bên thứ ba xuất hiện trên stack trace nhưng DumpAnalyzer chưa nhận biết được hãng sản xuất hoặc nhóm linh kiện, hãy mở `config/rules/driver_map.yaml`.

### Cấu trúc một mục driver:
```yaml
drivers:
  # Cấu trúc: <tên_file_sys_viết_thường>:
  rtwlanu.sys:
    component: "Realtek Wireless USB LAN Adapter"  # Tên thiết bị
    vendor: "Realtek"                            # Hãng sản xuất
    category: "network"                          # Phân loại linh kiện
    suspect_group: "driver"                      # Nhóm gán điểm nghi ngờ

  amdfendrs.sys:
    component: "AMD Crash Defender Driver"
    vendor: "AMD"
    category: "gpu"
    suspect_group: "gpu"
```

> [!IMPORTANT]
> - Tên driver **bắt buộc phải viết thường** kèm đuôi `.sys` (ví dụ: `nvlddmkm.sys`, `igdkmd64.sys`).
> - Phần mềm đã cấu hình cơ chế bảo vệ: Các module nhân của hệ điều hành Microsoft (`ntoskrnl.exe`, `hal.dll`, `win32k.sys`...) được xếp vào danh mục `ms_core_modules` và **tuyệt đối không bao giờ bị coi là thủ phạm phần cứng đơn độc**.

---

## 4. HƯỚNG DẪN BỔ SUNG QUY TẮC EVENT LOG (`event_rules.yaml`)

DumpAnalyzer tự động đối chiếu các sự kiện Windows Event Log xuất hiện trong cửa sổ 10 phút trước khi hệ thống sập để củng cố bằng chứng chẩn đoán.

### Cấu trúc một quy tắc sự kiện:
```yaml
event_rules:
  - id: "EVENT_WHEA_FATAL_ERROR"
    provider: "Microsoft-Windows-WHEA-Logger"  # Tên Event Provider
    event_id: 18                              # Mã sự kiện (Event ID)
    target_suspect: "cpu"                     # Nhóm nghi vấn được cộng điểm
    adds: 35                                  # Số điểm cộng thêm vào xác suất (%)
    cap: 85                                   # Điểm trần tối đa nhóm này có thể đạt
    note: "Phát hiện lỗi phần cứng phần cứng nghiêm trọng từ bộ xử lý (Machine Check Exception)"

  - id: "EVENT_DISK_CONTROLLER_TIMEOUT"
    provider: "disk"
    event_id: 129
    target_suspect: "storage"
    adds: 25
    cap: 80
    note: "Ổ đĩa không phản hồi lệnh IO trong khoảng thời gian timeout"
```

### Quy tắc điểm trần (`cap`):
Để tránh trường hợp một sự kiện thứ cấp đẩy xác suất lên 100% một cách phi thực tế, tham số `cap` giới hạn mức điểm tối đa mà sự kiện đó có thể đóng góp.

---

## 5. HƯỚNG DẪN MẪU HÌNH NHIỀU CRASH (`patterns.yaml`)

Khi phân tích nhiều lần sập trên cùng một máy tính hoặc toàn đội máy, file `patterns.yaml` kích hoạt các suy luận mức chuyên gia:

```yaml
patterns:
  - name: "Cùng một driver lặp lại nhiều lần"
    when:
      min_dumps: 3
      same_third_party_module_min: 3
    add:
      driver: 45
    note: "Driver này liên tục gây crash, xác suất cao do rò rỉ bộ nhớ hoặc lỗi phiên bản"
    next_steps:
      - "Gỡ sạch driver bằng tiện ích chuyên dụng (ví dụ DDU)"
      - "Cài đặt bản driver WHQL ổn định nhất từ nhà sản xuất OEM"

  - name: "Module lỗi thay đổi ngẫu nhiên, toàn bộ là module Microsoft"
    when:
      min_dumps: 3
      distinct_modules_min: 3
      only_microsoft_modules: true
    add:
      ram: 35
      psu: 25
    note: "Dấu hiệu phần cứng không ổn định (đặc biệt là lỗi bit nhớ RAM ngẫu nhiên hoặc sụt áp)"
```

---

## 6. LỆNH KIỂM TRA TÍNH HỢP LỆ TRƯỚC KHI TRIỂN KHAI

Trước khi lưu file và đưa vào sử dụng thực tế, hãy luôn chạy lệnh kiểm tra cú pháp:

```bash
# Trên dòng lệnh (CLI):
dumpanalyzer validate-rules
```
Hoặc trong giao diện PySide6: Mở **Tab Cài đặt** $\rightarrow$ bấm nút **"Kiểm tra tính hợp lệ của quy tắc (validate-rules)"**.

Phần mềm sẽ kiểm tra:
1. Cú pháp YAML có bị sai thụt đầu dòng (indentation) không.
2. Các mã lỗi hex có đúng định dạng không.
3. Tổng tỷ lệ phần trăm phân bổ nghi ngờ có hợp lệ không.
4. Có driver nào bị trùng lặp không.
