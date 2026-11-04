# HOTFIX 03 — GUI báo lỗi `"WindowsPath" object is not iterable` khi bấm Phân tích

> Dán nội dung từ mục "PROMPT" vào Antigravity. Làm **trước** Đợt 03 và Đợt 04 (các đợt đó dựa trên luồng phân tích này).

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer**. Người dùng chạy bản `.exe` (GUI), chọn nguồn dữ liệu "Máy cục bộ này", bấm phân tích và nhận thông báo:

```
Đã xảy ra lỗi khi phân tích: 'WindowsPath' object is not iterable
```

### 1. NGUYÊN TẮC

1. **Tái hiện trước, sửa sau:** viết test tái hiện đúng lỗi này, xác nhận test FAIL trên code hiện tại, rồi mới sửa.
2. Không thay đổi logic chấm điểm, luật YAML, cấu trúc CSDL hay định dạng báo cáo. Hotfix chỉ sửa cách **gọi** các hàm và cách **nối** các bước.
3. Giữ nguyên tên và chữ ký các hàm công khai của `engine/`, `collectors/`, `storage/` (đang được CLI và batch dùng đúng). Sửa phía GUI cho khớp với chúng, không sửa ngược.
4. Tiếng Việt cho mọi thông báo hướng tới người dùng. Mỗi nhóm sửa một commit riêng, nhánh `hotfix/gui-worker`.
5. **Không bịa:** nếu không chạy được `.exe` hoặc Event Log thật ở môi trường của bạn, ghi "chưa kiểm chứng trên Windows thật" và liệt kê bước để người dùng tự kiểm tra.

### 2. NGUYÊN NHÂN GỐC ĐÃ XÁC MINH (đối chiếu chữ ký hàm thật và mã nguồn v1.0.0; hãy mở file thực tế để xác nhận)

Lỗi nằm ở `src/dumpanalyzer/gui/worker.py` (lớp `AnalysisWorker.run`). CLI (`cli.py`) và batch (`engine/batch_analyzer.py`) gọi các hàm engine **đúng**, còn worker gọi **sai ở ít nhất 5 chỗ**, vì vậy luồng phân tích của GUI chưa từng chạy trọn vẹn:

| # | Worker đang làm | Chữ ký/hành vi thật | Hậu quả |
|---|---|---|---|
| 1 | `find_dumps(p_obj, ...)` với `p_obj` là một `Path` (và `find_dumps(self.folder_path, ...)` với một chuỗi) | `find_dumps(search_paths: List[str], ...)` lặp `for p in search_paths` | Với `Path` → **đúng lỗi người dùng gặp**. Với chuỗi (nguồn "thư mục") → lặp từng **ký tự**, ký tự `\` có thể bị hiểu là gốc ổ đĩa, nguy cơ quét rất nhiều file và kết quả sai |
| 2 | Coi kết quả `find_dumps` là danh sách `Path` (`d_path.name`, `calculate_sha256(d_path)`) | Trả về `List[Dict]`, đường dẫn nằm ở `item["path"]` | Lỗi kế tiếp ngay sau khi sửa lỗi 1 |
| 3 | `correlator.correlate_recent_updates(c, updates)` gọi **mỗi crash một lần** với một `Crash` | Tham số là `crashes: List[Crash]`; hàm tự tìm crash đầu tiên | `Crash` không lặp được → lỗi tương tự |
| 4 | `score_machine_crashes(crashes=..., rules=..., evidences=...)` rồi giải nén 6 giá trị | `score_machine_crashes(crashes_with_evidences: List[Tuple[Crash, List[Evidence]]], rules, settings) -> Dict` | Sai tên tham số và sai kiểu trả về |
| 5 | `generate_machine_finding(crashes=..., top_suspect=..., ...)` | `generate_machine_finding(machine_id, scored_result, rules) -> Finding` | Sai chữ ký |

**Vì sao test không bắt được:** trong `tests/test_gui.py` chỉ có test cờ hủy của worker; không có test nào chạy `run()`.

Các cách gọi **đúng** để làm chuẩn: `cli.py` (khoảng dòng 80, 587–588, 799–819) và `engine/batch_analyzer.py` (`analyze_fleet`, khoảng dòng 54, 139–152).

### 3. VIỆC CẦN LÀM

**3.1. Tái hiện bằng test (chạy trước khi sửa, phải FAIL)**

- `tests/test_dump_finder.py`: `find_dumps(Path(<thư mục fixtures>))` và `find_dumps("<chuỗi đường dẫn>")` hiện ném `TypeError` / lặp theo ký tự.
- `tests/test_gui_worker.py` (mới, xem 3.5): chạy `AnalysisWorker.run()` đồng bộ và bắt `error`.

**3.2. Làm `find_dumps` an toàn khi bị gọi sai** (`collectors/dump_finder.py`)

Ở đầu hàm, chuẩn hóa tham số: nếu `search_paths` là `str` hoặc `os.PathLike` thì bọc thành danh sách một phần tử. Hành vi với danh sách không đổi. Không đổi kiểu trả về. Thêm test: truyền chuỗi/`Path` trả đúng kết quả như truyền `[str(path)]`, **không** lặp theo ký tự.

**3.3. Dùng chung một luồng phân tích thay vì viết lại trong worker**

Để GUI và CLI không lệch nhau nữa, tách phần logic của `AnalysisWorker.run` ra module **mới** `src/dumpanalyzer/engine/pipeline.py`, ví dụ:

```python
def run_analysis(
    source_type: str,                      # "local" | "folder"
    folder_path: Optional[str],
    from_date, to_date,
    db_path: Optional[str],
    progress_cb: Callable[[int, str], None],
    status_cb: Callable[[str], None],
    is_cancelled: Callable[[], bool],
) -> Optional[Dict[str, Any]]:             # None nếu bị hủy
    ...
```

`AnalysisWorker.run` chỉ còn: tạo callback phát tín hiệu `progress`/`status_message`, gọi `run_analysis`, rồi phát `finished(payload)` hoặc `error(...)`. Hàm trả về cùng các khóa mà GUI đang dùng: `machine_info`, `crashes`, `finding`, `evidences`, `suspect_ranking`, `conflict_detected`, `patterns_matched`. **Hãy mở `gui/main_window.py` và các `tab_*.py` để kiểm tra chính xác khóa và kiểu dữ liệu GUI đang đọc rồi ánh xạ cho khớp**, trong đó:

- `suspect_ranking` ← `scored_result["suspect_scores"]`
- `conflict_detected` ← `scored_result["is_conflicted"]`
- `patterns_matched` ← `scored_result["patterns_matched"]`
- `finding.suspect_ranking` giữ như `batch_analyzer` đang làm (`setattr(finding, "suspect_ranking", ...)`).

**3.4. Sửa từng điểm gọi sai bên trong pipeline** (theo bảng ở mục 2)

1. Thu thập dump:
   - nguồn thư mục: `find_dumps([self.folder_path], from_date, to_date)`;
   - nguồn cục bộ: gom các đường dẫn tồn tại trong `settings["default_dump_paths"]` thành **một danh sách** `[str(p) ...]` rồi gọi `find_dumps(list, from_date, to_date)` một lần;
   - lấy `item["path"]` từ kết quả (là `Path`); dùng cho `calculate_sha256`, `copy_dump_safely`, hiển thị tên.
2. Bằng chứng:
   - Với mỗi crash: `correlate_events_to_crash(crash, events)`.
   - Gọi `correlate_recent_updates(crashes, updates)` **một lần** với toàn bộ danh sách crash; bằng chứng trả về đã gắn `crash_id` của crash đầu tiên, giữ nguyên.
   - Lưu bằng chứng bằng `db.insert_evidence`.
3. Chấm điểm: dựng `crashes_with_evidences = [(crash, [evidence của crash đó...]), ...]` (nhóm theo `crash_id`), gọi `score_machine_crashes(crashes_with_evidences, rules, settings)` và đọc kết quả từ dict.
4. Kết luận: `generate_machine_finding(machine_id, scored_result, rules)` rồi `db.insert_finding(finding)` (như `cli.py`).
5. Trường hợp **không tìm thấy dump nào** (hoặc không có sự kiện nào): không báo lỗi. Kết quả phải là một `finding` hợp lệ cho trường hợp "không đủ dữ kiện" (theo cách `score_machine_crashes([...])` trả về khi danh sách rỗng) kèm thông báo tiếng Việt thân thiện ("Không tìm thấy file dump. Máy có thể chưa bật ghi dump."). Đừng ném ngoại lệ.
6. Giữ nguyên khả năng **hủy an toàn** (`is_cancelled` kiểm tra giữa các bước; đóng DB khi hủy hoặc lỗi bằng `try/finally`).

**3.5. Thông báo lỗi dễ chẩn đoán hơn** (`gui/worker.py`, `gui/main_window.py`)

Hiện giao diện chỉ hiện `str(e)` nên rất khó tìm nguyên nhân. Sửa để:

- Thông báo lỗi nêu **loại lỗi**: `Đã xảy ra lỗi khi phân tích (<TênLoạiLỗi>): <nội dung>`.
- Hộp thoại lỗi có phần "Chi tiết kỹ thuật" (có thể mở/đóng) chứa traceback đầy đủ và đường dẫn tệp log, kèm nút **Sao chép chi tiết**.
- Traceback đầy đủ đã/ phải được ghi vào `logs\` (hiện dùng `logger.exception`; xác nhận tệp log có được tạo trong bản đóng gói).

### 4. TEST BẮT BUỘC

1. **`find_dumps`**: `str`/`Path` đơn lẻ và danh sách cho cùng kết quả; đường dẫn là **tệp** `.dmp` đơn lẻ vẫn tìm được (trường hợp `MEMORY.DMP`); đường dẫn không tồn tại bị bỏ qua êm.
2. **Pipeline đầu-cuối** (`tests/test_pipeline.py`): dùng các tệp trong `tests/fixtures/`; **mock** `read_system_events`, `collect_recent_windows_updates`, `collect_machine_info` (không phụ thuộc Windows) và dùng DB tạm. Kiểm tra: không ném lỗi, có `finding`, có `suspect_ranking`, số crash > 0, bằng chứng được lưu vào CSDL; lần chạy thứ hai dùng cache (cùng SHA256) cho kết quả tương đương.
3. **Hai nguồn dữ liệu:** nguồn `folder` (thư mục fixtures) và nguồn `local` (đặt `default_dump_paths` trỏ vào một thư mục và một tệp fixtures; mock Event Log).
4. **Không có dump:** thư mục rỗng/không tồn tại → kết quả "không đủ dữ kiện", không lỗi.
5. **Hủy:** `is_cancelled` trả về True giữa chừng → trả về `None`, không để lại kết nối DB mở.
6. **Worker đồng bộ** (`tests/test_gui_worker.py`, dùng fixture `qapp` hiện có, `QT_QPA_PLATFORM=offscreen`): gọi trực tiếp `AnalysisWorker(...).run()` (không `start()`), nối slot vào `finished` và `error`; xác nhận **không** phát `error`, và payload `finished` có đủ khóa mà GUI cần.
7. **Khói giao diện** (offscreen): nạp payload từ test 2 vào `MainWindow`, chuyển qua từng tab (Tổng quan, Chi tiết, Kết luận, Cài đặt) và bấm các nút xuất báo cáo (mock hộp thoại chọn tệp). Mục đích: phát hiện thêm lệch chữ ký ở phía hiển thị/xuất báo cáo. **Mọi lỗi mới tìm thấy phải sửa trong hotfix này nếu nhỏ, hoặc liệt kê rõ trong báo cáo nếu lớn.**
8. Đảm bảo CI chạy các test GUI (đã cài extra `gui`; đặt `QT_QPA_PLATFORM=offscreen` trong workflow nếu cần).

### 5. KIỂM TRA KIỂU (tùy chọn nhưng nên làm)

Lỗi ở mục 2 (sai kiểu `Path`/`dict`, sai tên tham số) sẽ bị kiểm tra kiểu bắt được, `ruff` thì không. Thêm vào CI một bước `python -m mypy src/dumpanalyzer/engine/pipeline.py src/dumpanalyzer/gui/worker.py --ignore-missing-imports` (thêm `mypy` vào nhóm `dev`). Nếu số lỗi từ module khác quá nhiều thì giới hạn kiểm tra ở 2 file này. Không che lỗi bằng `continue-on-error`.

### 6. NGUYÊN TẮC HOÀN THÀNH

- `python -m ruff check src` và `python -m pytest -q` PASS (kể cả test GUI mới); workflow GitHub xanh.
- Cập nhật `CHANGELOG.md` (mục "Sửa lỗi: luồng phân tích GUI gọi sai hàm engine"), tăng số phiên bản bản vá theo CHANGELOG hiện tại.
- Không đổi kết quả chấm điểm: với cùng bộ dữ liệu, kết luận do GUI và CLI sinh ra phải **trùng nhau**; thêm một test so sánh.

### 7. BÁO CÁO (tiếng Việt)

1. Xác nhận đã tái hiện đúng lỗi (test nào FAIL trước khi sửa).
2. Từng điểm gọi sai đã sửa (5 điểm ở mục 2) và các điểm sai khác phát hiện thêm (nếu có), kèm file/hàm.
3. Kết quả `pytest`, `ruff`, `mypy` (nếu có) và kết quả workflow GitHub.
4. Những gì **chưa kiểm chứng** trên Windows thật và bước để người dùng tự kiểm tra.
5. Quan sát (không sửa trong hotfix này): `analyze_fleet` trong chế độ `batch` đang truyền danh sách bằng chứng rỗng khi chấm điểm. Hãy xác nhận đó là chủ ý hay thiếu sót và ghi vào báo cáo.

---

## PHỤ LỤC — Người dùng tự kiểm tra sau khi có bản build mới

1. Mở GUI, chọn "Máy cục bộ này", bấm phân tích. Phải ra kết quả hoặc thông báo "không tìm thấy file dump", không còn lỗi `'WindowsPath' object is not iterable`.
2. Thử "Chọn thư mục dump" với một thư mục có vài file `.dmp`.
3. Nếu còn lỗi, mở "Chi tiết kỹ thuật" trong hộp thoại, bấm **Sao chép chi tiết** và gửi lại, hoặc gửi tệp log trong thư mục `logs\`.
