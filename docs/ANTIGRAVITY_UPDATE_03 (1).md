# ĐỢT CẬP NHẬT 03 — NÂNG ĐỘ CHÍNH XÁC KẾT LUẬN + KHUNG TEST PHẦN CỨNG (v1.1.0)

> Dán toàn bộ nội dung từ mục "PROMPT" vào Antigravity.
> Đợt này gồm: **Phần 0** sửa lỗi build GitHub, rồi **4 hạng mục phát triển** (Phần 1–4). Đề xuất số 1 trong lộ trình ("sửa lỗi nền") chính là **Đợt 02**, là điều kiện tiên quyết.

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer** (Python, PySide6, SQLite, YAML rules). Mục tiêu của công cụ là **khoanh vùng thiết bị nghi ngờ** cho IT, không phải đưa ra kết luận tuyệt đối. Vì vậy mọi tính năng mới phải: (1) nói rõ bằng chứng nào ủng hộ, bằng chứng nào phản bác, còn thiếu gì; (2) không tuyên bố chắc chắn khi dữ liệu yếu. Người dùng KHÔNG biết lập trình, mọi thay đổi phải có test và báo cáo bằng tiếng Việt.

### 0. NGUYÊN TẮC CHUNG

1. **Kiểm tra điều kiện tiên quyết:** xác nhận Đợt 02 đã hoàn thành (CHANGELOG có mục v1.0.1, nhóm lỗi A1–A4 đã sửa và có test, pytest PASS). Nếu chưa, DỪNG và báo cáo, không làm tiếp.
2. Làm theo thứ tự: **Phần 0 → 1 → 2 → 3 → 4 → 5.** Mỗi phần = một nhánh con hoặc ít nhất một nhóm commit riêng, message dạng `feat(sysinfo): ...` / `fix(ci): ...`. Nhánh chính của đợt: `feature/update-03`; riêng Phần 0 dùng nhánh `fix/ci-ruff` và gộp trước.
3. Với mỗi hạng mục: viết test trước hoặc cùng lúc, chạy `python -m pytest -q` và `python -m ruff check src` sau mỗi phần. Tất cả phải xanh mới sang phần kế tiếp.
4. Tương thích ngược: thêm cột/bảng bằng migration an toàn trong `storage/db.py` (không mất dữ liệu cũ); khóa YAML mới thiếu → dùng mặc định; file YAML cũ của người dùng vẫn chạy.
5. **Không bịa.** Những gì không thể kiểm chứng ngoài Windows thật (lệnh PowerShell/cdb, ID sự kiện, định dạng đầu ra) phải ghi "CHƯA KIỂM CHỨNG — cần người dùng test trên Windows" kèm lệnh cụ thể. Mọi ID sự kiện/định dạng chưa chắc chắn phải đặt trong file YAML để người dùng sửa, không hard-code.
6. Không thay đổi file dump gốc. Không tự sửa registry, cấu hình khởi động (bcdedit), không chạy `chkdsk /f` hay bất kỳ lệnh ghi nào lên đĩa mà không có xác nhận rõ ràng của người dùng.
7. Dữ liệu chỉ lưu cục bộ. Không gửi gì ra ngoài Internet (ngoài việc tải symbol của cdb như hiện có).

---

### PHẦN 0 — SỬA LỖI BUILD GITHUB ACTIONS (làm đầu tiên, gộp riêng)

**Lỗi ghi nhận từ GitHub Actions** (job `build-windows`, runner `windows-latest`, shell PowerShell):

```
Run ruff check src --select F
ruff: ...ps1:2
Line |
   2 |  ruff check src --select F
     |  ~~~~
     | The term 'ruff' is not recognized as a name of a cmdlet, function, script file, or executable program.
Error: Process completed with exit code 1.
```

**Nguyên nhân** (đối chiếu với bản v1.0.0): bước "Install Dependencies" cài `pip install -e .[gui,report,dev]`, nhưng nhóm `dev` trong `pyproject.toml` chỉ có `pytest` và `pyinstaller`, không có `ruff`. Hãy mở file thực tế trong repo để xác nhận trước khi sửa.

**Cần làm:**

1. `pyproject.toml`: thêm `"ruff>=0.5.0"` vào nhóm `dev`, và thêm cấu hình:

```toml
[tool.ruff]
target-version = "py311"
line-length = 120

[tool.ruff.lint]
select = ["F"]
```

2. `.github/workflows/build.yml`: đặt bước lint **sau** "Install Dependencies" và **trước** "Run Pytest Suite", gọi qua `python -m ruff` để không phụ thuộc PATH:

```yaml
      - name: Lint (ruff)
        run: |
          python -m ruff check src
```

3. Nếu ruff báo lỗi thật trong `src/`, sửa từng lỗi trong mã (mỗi nhóm một commit). KHÔNG dùng `--exit-zero`, `|| true`, `continue-on-error`, và không tắt luật chỉ để cho qua (nếu bắt buộc bỏ qua một dòng thì dùng `# noqa: <mã>` kèm lý do).
4. Chạy cục bộ trước khi đẩy lên:

```bash
pip install -e ".[gui,report,dev]"
python -m ruff check src
python -m pytest -q
```

**Hoàn thành khi:** workflow `Build & Release DumpAnalyzer` xanh toàn bộ (Install → Lint → Pytest → Build → Upload). Nếu không chạy được workflow từ môi trường của bạn, ghi "chưa xác nhận trên GitHub Actions".

---

### PHẦN 1 — THU THÊM DỮ LIỆU ĐỂ TĂNG BẰNG CHỨNG (đề xuất số 2)

**Tinh thần:** thêm nguồn dữ liệu để có bằng chứng *độc lập* và *mạnh*. Mọi ngưỡng/ID nằm trong YAML.

**1.1. Mở rộng phân tích bằng cdb**
(`analyzer/cdb_runner.py`, `analyzer/cdb_parser.py`; thêm trường vào `CdbAnalysisResult`; lưu vào bảng `crash` hoặc một cột JSON `extra_json` mới)

- Lấy `FAILURE_BUCKET_ID` từ `!analyze -v` (để gom crash giống nhau ở Phần 2).
- Với Bug Check **0x124**: chạy `!errrec <địa chỉ>` với địa chỉ là tham số thứ 2 của bug check (con trỏ tới bản ghi lỗi WHEA); trích loại thành phần lỗi (CPU/cache/bộ nhớ/PCIe...) nếu đọc được.
- `!chkimg -d nt` (kiểm tra mã nhân Windows trong dump có bị sai khác so với bản gốc không); trích số byte/khối sai khác. Sai khác là gợi ý RAM hỏng hoặc bit bị lật.
- Với module nghi vấn bên thứ ba: `lmvm <module>` để lấy phiên bản và ngày của driver → tính "tuổi driver" (tháng).
- **Yêu cầu bắt buộc:** parser phải **chịu lỗi** (lệnh timeout, symbol thiếu, định dạng khác mong đợi → bỏ qua phần đó, ghi cảnh báo, KHÔNG làm hỏng phân tích hiện tại). Vì chưa có đầu ra thật, hãy:
  - viết parser dựa trên định dạng tài liệu công khai, kèm fixture tổng hợp ghi rõ "dữ liệu tổng hợp";
  - thêm tùy chọn `--save-cdb-samples` lưu đầu ra thô của các lệnh mới vào thư mục `workspace/cdb_samples/` để người dùng gửi lại mẫu thật cho việc hiệu chỉnh parser.
  - Ghi "CHƯA KIỂM CHỨNG với dump thật".

**1.2. Mở rộng Event Log** (`collectors/eventlog.py`, `config/rules/event_rules.yaml`)

Đối chiếu với luật hiện có, **chỉ thêm những gì còn thiếu**, mỗi luật có `strength` (xem Phần 3), `cap` và nhóm nghi ngờ:

- Kernel-PnP ID 219 (driver không nạp được), Code Integrity ID 3033/3063 (driver không đạt kiểm tra chữ ký).
- Application Error ID 1000 trong **Application log**: đếm số ứng dụng khác nhau chết trong cửa sổ thời gian (nhiều ứng dụng chết ngẫu nhiên là gợi ý RAM/phần cứng, mức vừa). Cần thêm khả năng đọc log Application, không chỉ System.
- Display ID 4101 (TDR màn hình) cho nhóm GPU.
- Kernel-Processor-Power ID 37 (CPU bị giới hạn do firmware/nhiệt) — **ID cần người dùng xác minh trên máy thật**, đặt trong YAML.
- Event 41: đọc thêm các trường trong EventData (`BugcheckCode`, `SleepInProgress`, `PowerButtonTimestamp`) và hiển thị trong Tab chi tiết.

**1.3. Thu thập thông tin hệ thống** — module mới `collectors/sysinfo.py`, bảng mới `system_info(machine_id, collected_at, key, value, raw_json)` hoặc tương đương:

| Nhóm | Nguồn (PowerShell/CIM) | Dùng để |
|---|---|---|
| RAM | `Win32_PhysicalMemory`: dung lượng, `Speed`, `ConfiguredClockSpeed`, nhà sản xuất, part number, số thanh | Ghi nhận cấu hình; cờ `configured > speed` là **gợi ý** ép xung (mức yếu, không kết luận) |
| Ổ đĩa | `Get-PhysicalDisk` + `Get-StorageReliabilityCounter`: `HealthStatus`, `OperationalStatus`, nhiệt độ, độ mòn, `PowerOnHours`, các bộ đếm lỗi đọc/ghi | Bằng chứng mạnh cho nhóm storage nếu có lỗi/độ mòn cao |
| BIOS/CPU/GPU | `Win32_BIOS`, `Win32_Processor`, `Win32_VideoController` | Ghi nhận phiên bản BIOS/ngày BIOS, đời CPU, phiên bản và ngày driver GPU |

- Đặt ngưỡng (độ mòn %, BIOS cũ hơn N năm, driver cũ hơn N tháng...) trong file mới `config/rules/system_rules.yaml`, không hard-code.
- Chỉ thu cho máy đang chạy phần mềm. Nếu chế độ batch đã có cơ chế truy cập máy khác thì dùng lại, **không tự thêm cơ chế truy cập từ xa mới.**
- Mọi lệnh phải **chỉ đọc**, có timeout, lỗi một nguồn không làm hỏng các nguồn khác; hiển thị cảnh báo thay vì im lặng (giống Nhóm C của Đợt 02).

**1.4. Nhập tuổi máy/lịch sử từ AppSheet** (không dùng API Google trong đợt này)

- Thêm lệnh/ nút "Nhập danh sách thiết bị từ CSV" (người dùng xuất bảng thiết bị từ Google Sheets/AppSheet ra CSV).
- Ánh xạ cột cấu hình được trong `settings.yaml` (ví dụ: `tên máy`, `ngày mua`, `ngày hết bảo hành`, `số lần sửa`, `RAM`, `ghi chú`). Khớp với máy bằng tên máy (không phân biệt hoa thường).
- Lưu vào bảng `asset_info`. Dùng làm bằng chứng yếu–vừa qua `system_rules.yaml` (ví dụ máy trên N năm tuổi nâng nhẹ điểm phần cứng; máy từng sửa nhiều lần cũng vậy). Không bắt buộc phải có.
- Không lưu mật khẩu hay khóa truy cập nào trong repo.

**Test tối thiểu Phần 1:** parser cdb với fixture tổng hợp (có và thiếu từng lệnh), parser sysinfo với JSON mẫu, nhập CSV với cột thiếu/dư, luật sysinfo cho ra bằng chứng đúng nhóm, lỗi từng nguồn không làm sập tổng thể.

---

### PHẦN 2 — VÒNG PHẢN HỒI + NHÌN THEO LỊCH SỬ VÀ ĐỘI MÁY (đề xuất số 3)

**2.1. Nút phản hồi "Kết luận đúng / sai / chưa rõ"**

- Bảng mới `feedback`: `id, machine_id, analysis_ref (bám vào bản ghi kết luận hiện có — hãy xem schema thực tế để chọn đúng bảng), predicted_group, predicted_confidence, verdict (dung|sai|chua_ro), actual_cause, note, created_at`.
- GUI: trong Tab kết luận của từng máy thêm 3 nút + ô chọn "Nguyên nhân thực tế" (danh sách nhóm nghi ngờ + "Khác") + ô ghi chú. CLI: `dumpanalyzer feedback add|list|stats`.
- `feedback stats`: tỷ lệ kết luận hạng 1 đúng, tỷ lệ nằm trong top 3, thống kê theo nhóm nghi ngờ và theo mức độ tin cậy; xuất được sang báo cáo Excel (sheet mới). Chỉ hiển thị tỷ lệ khi có ít nhất 10 ca có đánh giá; dưới đó ghi "chưa đủ dữ liệu".
- **Không** tự động chỉnh trọng số trong đợt này; chỉ thu thập và thống kê.

**2.2. Lịch sử theo máy**

- Kiểm tra `score_machine_crashes` có dùng **toàn bộ crash đã lưu của máy** trong khoảng `history_lookback_days` (khóa mới trong `settings.yaml`, mặc định 180) hay chỉ lần quét hiện tại. Nếu chỉ dùng lần quét hiện tại thì sửa lại; báo cáo rõ hiện trạng trước khi sửa.
- Hiển thị dòng thời gian crash của máy (ngày, mã lỗi, module) trong Tab chi tiết.

**2.3. Nhìn theo đội máy**

- Màn hình/sheet mới "Tổng quan đội máy": gom crash theo `FAILURE_BUCKET_ID` (Phần 1.1) và theo `suspect_driver`/module bên thứ ba; liệt kê nhóm xuất hiện trên **≥ N máy** trong **D ngày** (N, D trong `settings.yaml`; mặc định 3 máy / 30 ngày).
- Thêm luật bằng chứng mức vừa: "driver/bucket X cũng gây crash trên K máy khác" — qua `system_rules.yaml` hoặc `patterns.yaml`, cộng cho nhóm driver/phần mềm, KHÔNG cộng cho phần cứng.
- Phát hiện sự trùng thời điểm với bản cập nhật Windows/driver nếu dữ liệu có (dùng lại cơ chế correlate update hiện có).

**Test tối thiểu Phần 2:** ghi và đọc feedback; thống kê với 0, 5, 12 ca; gom bucket nhiều máy; luật đội máy chỉ cộng đúng nhóm; migration không làm mất dữ liệu cũ.

---

### PHẦN 3 — TÁCH "ĐỘ TIN CẬY" KHỎI "ĐIỂM NGHI NGỜ" + GỢI Ý BƯỚC TIẾP THEO (đề xuất số 4)

**3.1. Mô hình bằng chứng có độ mạnh, chiều và nhóm độc lập**

- Thêm cột `strength` (`strong|medium|weak`), `polarity` (`support|refute`, mặc định `support`), `group_id` (nhóm độc lập: các bằng chứng cùng nguồn gốc có cùng `group_id`) vào bảng `evidence` (migration tương thích ngược; dữ liệu cũ mặc định `weak/support`).
- Thêm `strength` và `group_id` vào từng luật trong `event_rules.yaml`, `system_rules.yaml`, `patterns.yaml`. Gợi ý khởi điểm: WHEA có thành phần rõ, Disk 7/11/51/153, stornvme 129, SMART lỗi, driver lặp lại ở nhiều dump = **strong**; nhiều mã lỗi khác nhau/module ngẫu nhiên, TDR, sau cập nhật = **medium**; chỉ có mã bug check, một dump đơn lẻ, cờ ép xung RAM = **weak**.
- Bằng chứng **phản bác** (`refute`) làm giảm điểm nhóm tương ứng (sàn 0) và được hiển thị riêng.

**3.2. Hai chỉ số riêng trong kết quả**

- `suspicion_share` = tỷ trọng nghi ngờ hiện có (giữ nguyên cách tính để không phá dữ liệu cũ).
- `confidence` = `cao | trung_binh | thap`, tính theo chính sách trong `settings.yaml` (`confidence_policy`):
  - **cao:** ≥ 2 bằng chứng *strong* ủng hộ nhóm đứng đầu với ≥ 2 `group_id` khác nhau, và không có bằng chứng phản bác strong.
  - **trung bình:** 1 bằng chứng strong, hoặc ≥ 2 bằng chứng medium độc lập.
  - **thấp:** các trường hợp còn lại (đặc biệt: chỉ có mã bug check, chỉ có `header_only`/`log_only`, chỉ một dump).
- Thay mọi chỗ đang dùng điểm % để gán nhãn "cao/trung bình/thấp" bằng `confidence` mới. Cập nhật báo cáo và GUI: hiển thị **cả hai** chỉ số, kèm giải thích ngắn "vì sao nhãn này".

**3.3. Báo cáo/GUI theo cấu trúc mới**

Mỗi máy hiển thị: **Nhóm nghi ngờ hàng đầu** → **Độ tin cậy** → **Bằng chứng ủng hộ** → **Bằng chứng phản bác** → **Còn thiếu dữ liệu gì** → **Nên làm tiếp**.

**3.4. Bộ gợi ý "bước kiểm tra tiếp theo"** — file mới `config/rules/next_steps.yaml`

- Cho từng nhóm (`ram`, `storage`, `driver`, `gpu`, `psu`, `cpu`, `thermal`, `software`, `unknown`): danh sách bước, mỗi bước có điều kiện kích hoạt (ví dụ độ tin cậy thấp, chưa có test RAM, chưa có cdb...).
- Phát hiện "dữ liệu còn thiếu" bằng mã, ví dụ: chưa có cdb/symbol → "cài WinDbg/cdb để lấy tên driver"; dump kiểu triage/nhỏ → "bật Kernel memory dump"; chỉ có một dump → "theo dõi thêm, thu thêm dump"; chưa chạy test liên quan → "chạy bài test ở Tab Kiểm tra phần cứng" (Phần 4).
- Với nhóm `driver` có thể nêu Driver Verifier như một gợi ý nâng cao, nhưng nội dung phải ghi cảnh báo rõ: chỉ bật có kiểm soát cho driver nghi vấn, có thể gây BSOD lặp, cách tắt là `verifier /reset`. **Phần mềm tuyệt đối không tự bật Driver Verifier.**
- Văn bản gợi ý viết tiếng Việt, ngắn gọn, do người dùng chỉnh sửa được.

**3.5. Chuẩn bị hiệu chỉnh**

- Khi `feedback stats` (Phần 2) có ≥ 10 ca, hiển thị trên báo cáo dòng "Khi hệ thống đánh giá 'cao', đã đúng X/Y ca". Không tự động đổi trọng số.

**Test tối thiểu Phần 3:** chỉ có mã bug check → `confidence=thap` dù điểm cao; 2 bằng chứng strong từ 2 `group_id` → `cao`; 2 bằng chứng strong cùng `group_id` → không đạt `cao`; bằng chứng refute làm giảm điểm và không âm; dữ liệu cũ (không có strength) vẫn chạy; `next_steps` sinh đúng với từng trường hợp thiếu dữ liệu.

---

### PHẦN 4 — KHUNG PLUGIN KIỂM TRA PHẦN CỨNG (đề xuất số 5)

**Giới hạn kỹ thuật cần tôn trọng:** không thể kiểm tra RAM đầy đủ khi Windows đang chạy. Vì vậy đợt này **KHÔNG** tự viết bộ test RAM trong hệ điều hành, **KHÔNG** tự khởi động vào môi trường test, **KHÔNG** sửa cấu hình khởi động. Chỉ làm khung + 3 plugin an toàn bên dưới.

**4.1. Khung plugin** — package mới `src/dumpanalyzer/hwtests/` (đừng đặt tên trùng thư mục `tests/`):

- Lớp cơ sở `HardwareTest` có: `id, name, description, group` (nhóm nghi ngờ liên quan), `requires_reboot, requires_admin, estimated_minutes`, `check_prerequisites()`, `start()`, `collect_result()`.
- `TestResult`: `status` ∈ {`passed, failed, inconclusive, pending, not_run}`, `details`, `started_at, finished_at`, `raw`.
- Bảng `test_run` lưu mọi lần chạy. Mỗi kết quả được chuyển thành `Evidence` theo bảng quy đổi nằm trong `config/rules/test_rules.yaml`:
  - `failed` → **strong, support** cho nhóm của bài test;
  - `passed` → **weak hoặc medium, refute** cho nhóm đó (RAM `passed` chỉ nên là weak vì lỗi RAM có thể chập chờn);
  - `inconclusive/pending/not_run` → không sinh bằng chứng.

**4.2. Ba plugin ban đầu**

a) **`storage_health`** (không cần khởi động lại, cần quyền Admin cho `chkdsk`):
   - đọc `Get-PhysicalDisk`/`Get-StorageReliabilityCounter` (dùng lại dữ liệu Phần 1.3);
   - chạy `chkdsk <ổ> /scan` ở chế độ **chỉ quét, không sửa**; xác định kết quả bằng mã thoát và đầu ra theo cấu hình YAML; không bao giờ dùng `/f`, `/r`, `/spotfix`;
   - có timeout cấu hình và có thể hủy.

b) **`windows_memory_diagnostic`**:
   - nút "Mở Windows Memory Diagnostic" chỉ **mở `mdsched.exe`** để người dùng tự chọn khởi động lại ngay/sau; phần mềm ghi `test_run` trạng thái `pending` kèm thời điểm bắt đầu;
   - sau khi máy khởi động lại, `collect_result()` đọc các sự kiện từ provider `Microsoft-Windows-MemoryDiagnostics-Results` phát sinh sau thời điểm bắt đầu;
   - ánh xạ **ID sự kiện → đạt/không đạt** nằm trong `test_rules.yaml` (khóa `result_event_map`). **Không hard-code giả định.** Nếu tìm thấy sự kiện nhưng ID không có trong ánh xạ → `inconclusive`, hiển thị nội dung sự kiện và hai nút "Đánh dấu đạt / Đánh dấu không đạt" để người dùng tự xác nhận; ghi rõ "CHƯA KIỂM CHỨNG ID trên Windows thật".

c) **`external_test_import`** (cho MemTest86 / Memtest86+ / OCCT / Prime95 chạy ngoài phần mềm):
   - biểu mẫu nhập tay: tên công cụ, nhóm (RAM/CPU/ổ đĩa...), số lượt chạy, số lỗi, thời lượng, ngày giờ, đường dẫn tới file báo cáo/ảnh chụp (chỉ lưu đường dẫn);
   - quy tắc mặc định trong YAML: số lỗi > 0 → `failed`; 0 lỗi và số lượt ≥ `min_passes` (mặc định 4, người dùng sửa được) → `passed`; còn lại → `inconclusive`;
   - nút "Tạo phiếu hướng dẫn test RAM" xuất một trang hướng dẫn ngắn (tiếng Việt) cách khởi động công cụ test từ USB, số lượt khuyến nghị và cách ghi kết quả để nhập lại vào phần mềm.

**4.3. Giao diện:** Tab mới "Kiểm tra phần cứng": danh sách plugin (tên, nhóm, cần khởi động lại?, cần Admin?, thời gian dự kiến), trạng thái lần chạy gần nhất, nút chạy/mở/nhập kết quả, lịch sử chạy, cảnh báo quyền Admin. Kết quả tự đi vào Phần 3 (độ tin cậy) và `next_steps` (ví dụ RAM `failed` → gợi ý thay/tháo thử từng thanh; RAM `passed` → gợi ý nghi ngờ chuyển sang nhóm khác nhưng vẫn lưu ý lỗi chập chờn).

**4.4. An toàn:** mọi hành động ghi/thay đổi hệ thống đều cần xác nhận rõ; ghi log đầy đủ lệnh đã chạy; không bao giờ chạy test nặng khi chưa có xác nhận.

**Test tối thiểu Phần 4:** chuyển trạng thái test thành Evidence đúng nhóm/độ mạnh/chiều; `passed` RAM chỉ sinh refute yếu; ánh xạ ID chưa biết → `inconclusive`; import ngoài với 0 lỗi nhưng 2 lượt → `inconclusive`; plugin không có quyền Admin báo đúng điều kiện; không có lệnh nguy hiểm trong chuỗi lệnh sinh ra (test chuỗi: không chứa `/f`, `/r`, `bcdedit`).

---

### PHẦN 5 — TÀI LIỆU, KIỂM THỬ TỔNG, PHÁT HÀNH

1. Cập nhật `docs/RULES_GUIDE.md` (khóa mới: `strength`, `group_id`, `polarity`, `cap`, `system_rules.yaml`, `test_rules.yaml`, `next_steps.yaml`, `confidence_policy`) và `README.md` (tính năng mới, giới hạn).
2. Cập nhật `CHANGELOG.md` mục `[v1.1.0]`; tăng phiên bản trong `pyproject.toml` lên `1.1.0`.
3. Chạy toàn bộ `python -m ruff check src` và `python -m pytest -q`; workflow GitHub phải xanh; tag `v1.1.0` chỉ khi mọi thứ xanh.

### KHÔNG LÀM TRONG ĐỢT NÀY

- Không viết bộ test RAM chạy trong Windows, không khởi động WinPE, không dùng `bcdedit`.
- Không dùng API Google (chỉ nhập CSV), không đẩy dữ liệu ra ngoài.
- Không tự chỉnh trọng số bằng học máy/hồi quy (chưa đủ dữ liệu phản hồi).
- Không tự bật Driver Verifier hay bất kỳ thay đổi hệ thống nào mà người dùng chưa xác nhận.
- Không thay đổi các bước đóng gói PyInstaller và phát hành, ngoài việc thêm bước lint ở Phần 0.

### ĐỊNH DẠNG BÁO CÁO CUỐI (tiếng Việt, theo từng Phần 0–5)

1. Đã làm gì (file và hàm/bảng/khóa YAML mới).
2. Test đã thêm và kết quả `pytest`/`ruff`.
3. Điểm **CHƯA KIỂM CHỨNG** trên Windows thật/dump thật, kèm đúng lệnh hoặc thao tác để người dùng kiểm tra.
4. Việc bỏ dở hoặc quyết định đã đưa ra và lý do.
5. Cuối báo cáo: danh sách commit, kết quả workflow GitHub Actions, phiên bản/tag.

---

## PHỤ LỤC — Việc người dùng tự kiểm tra trên Windows sau khi Antigravity xong

1. Trang Actions của repo: bước Lint và Pytest đều xanh.
2. Chạy `dumpanalyzer scan --save-cdb-samples` trên máy có dump thật; gửi lại thư mục `workspace/cdb_samples/` để hiệu chỉnh parser `!errrec`, `!chkimg`, `lmvm`.
3. Chạy `dumpanalyzer events --debug-ps` và kiểm tra các sự kiện mới (Application Error 1000, Kernel-PnP 219, Code Integrity...).
4. Mở Tab "Kiểm tra phần cứng": thử `storage_health` và mở `mdsched`; sau khi khởi động lại, kiểm tra ID sự kiện kết quả và điền vào `test_rules.yaml`.
5. Nhập thử CSV danh sách thiết bị xuất từ AppSheet/Google Sheets và đối chiếu tên máy có khớp không.
6. Dùng nút "Kết luận đúng/sai" sau mỗi ca sửa chữa thật để tích lũy dữ liệu.
