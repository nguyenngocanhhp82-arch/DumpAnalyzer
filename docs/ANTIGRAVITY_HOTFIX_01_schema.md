# HOTFIX 01 — Bản đóng gói (.exe) thiếu file `schema.sql`

> Dán nội dung từ mục "PROMPT" vào Antigravity. Nên gộp hotfix này **trước** khi làm Đợt 03.

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer**. Người dùng chạy bản `.exe` đã đóng gói (PyInstaller, chế độ onedir), chọn nguồn dữ liệu "Máy cục bộ này" và bấm phân tích hệ thống thì gặp lỗi:

```
FileNotFoundError: Không tìm thấy file schema SQL tại ...\DumpAnalyzer\...\storage\schema.sql
```

Người dùng kiểm tra và **không thấy thư mục `storage\`** trong thư mục chương trình.

### 1. NGUYÊN NHÂN (đã đối chiếu với mã nguồn v1.0.0 — hãy mở file thực tế hiện tại để xác nhận)

- `src/dumpanalyzer/storage/db.py` (khoảng dòng 43) nạp schema bằng `Path(__file__).resolve().parent / "schema.sql"`.
- `DumpAnalyzer.spec` đang để `datas=[]` ở **cả hai** `Analysis` (GUI và CLI), nên file `schema.sql` (file dữ liệu không phải `.py` duy nhất trong `src/`) **không được đưa vào gói**.
- Mã Python nằm trong kho nén của chương trình nên không có thư mục `storage\` thật trên đĩa. Khi chạy từ mã nguồn thì file có sẵn, vì vậy 85 test vẫn PASS nhưng bản `.exe` thì hỏng.

Đây là lỗi đóng gói, không phải lỗi logic phân tích.

### 2. VIỆC CẦN LÀM

Tạo nhánh `hotfix/schema-packaging` từ `main`. Mỗi mục dưới đây một commit riêng.

**2.1. Đưa `schema.sql` vào gói đóng gói** (`DumpAnalyzer.spec`)

Thêm vào **cả hai** `Analysis` (GUI và CLI), vì cả hai đều dùng CSDL:

```python
SCHEMA_SQL = str(Path(SPECPATH) / 'src' / 'dumpanalyzer' / 'storage' / 'schema.sql')

# trong Analysis(...):
datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')],
```

(`SPECPATH` là biến PyInstaller tự cung cấp, trỏ tới thư mục chứa file spec.) Sau khi build, file phải nằm ở `dist\DumpAnalyzer\_internal\dumpanalyzer\storage\schema.sql` (với PyInstaller 6.x). Hãy xác nhận đúng vị trí thực tế sau khi build.

**2.2. Làm cho `db.py` tìm file chắc chắn hơn** (`src/dumpanalyzer/storage/db.py`)

Tách hàm tìm file, thử lần lượt các vị trí, và nếu thất bại thì báo lỗi **liệt kê các đường dẫn đã thử** kèm gợi ý bằng tiếng Việt:

```python
import sys
from pathlib import Path

def _find_schema_file() -> Path:
    tried = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        tried.append(Path(base) / "dumpanalyzer" / "storage" / "schema.sql")
    tried.append(Path(__file__).resolve().parent / "schema.sql")
    for p in tried:
        if p.is_file():
            return p
    raise FileNotFoundError(
        "Không tìm thấy schema.sql. Đã thử:\n  " + "\n  ".join(str(p) for p in tried)
        + "\nGợi ý: bản đóng gói thiếu file dữ liệu, hãy build lại bằng DumpAnalyzer.spec mới."
    )
```

Dùng hàm này thay cho đoạn `Path(__file__).resolve().parent / "schema.sql"` hiện tại. Không đổi nội dung `schema.sql` hay logic migration.

**2.3. Khai báo dữ liệu gói cho cài đặt bằng pip** (`pyproject.toml`)

```toml
[tool.setuptools.package-data]
dumpanalyzer = ["storage/schema.sql"]
```

**2.4. Rà soát các file dữ liệu khác trong bản đóng gói**

- Tìm mọi chỗ trong `src/` đọc file bằng `__file__`, `open(...)`, `Path(...)` mà không phải mã `.py` (ví dụ mẫu báo cáo, biểu tượng, file mẫu). Hiện tại tôi chỉ thấy `schema.sql`, hãy xác nhận lại. Nếu có thêm, đưa vào `datas` tương tự.
- Thư mục `config/` được cố ý để **bên ngoài** gói (do `build_exe.py` sao chép cạnh file `.exe`), giữ nguyên thiết kế đó. Chỉ cần bảo đảm nếu thiếu `config/` thì phần mềm báo lỗi rõ ràng bằng tiếng Việt chứ không sập.

**2.4b. Bước kiểm tra trong GitHub Actions** (`.github/workflows/build.yml`)

Thêm sau bước "Build Executable Package with PyInstaller" và trước bước tải artifact:

```yaml
      - name: Kiểm tra gói có đủ file dữ liệu
        run: |
          $f = Get-ChildItem -Path dist\DumpAnalyzer -Recurse -Filter schema.sql
          if (-not $f) { Write-Error "Thiếu schema.sql trong gói đóng gói"; exit 1 }
          $f | ForEach-Object { $_.FullName }
```

Thử thêm một bước chạy nhanh bản CLI đã đóng gói bằng một lệnh có khởi tạo CSDL (hãy xem `cli.py` để chọn lệnh phù hợp) và kiểm tra `$LASTEXITCODE`. Lưu ý file `.exe` yêu cầu quyền Administrator (`uac_admin=True`); nếu runner không cho chạy, ghi rõ trong báo cáo và giữ lại bước kiểm tra sự tồn tại file ở trên. Không được che lỗi bằng `continue-on-error`.

### 3. TEST (`tests/test_packaging.py`, chạy được trên Linux)

1. `_find_schema_file()` tìm được file khi chạy từ mã nguồn.
2. Giả lập chế độ đóng gói: đặt `sys._MEIPASS` về thư mục tạm có sẵn `dumpanalyzer/storage/schema.sql`, trỏ `__file__` của module tới nơi không có file → hàm vẫn tìm thấy qua `_MEIPASS`.
3. Khi không tìm thấy ở đâu cả → ném `FileNotFoundError` có liệt kê đường dẫn đã thử.
4. Đọc `DumpAnalyzer.spec` và xác nhận `schema.sql` xuất hiện trong `datas` của **cả hai** `Analysis`.
5. Đọc `pyproject.toml` và xác nhận có khai báo `package-data` cho `schema.sql`.

### 4. NGUYÊN TẮC

- Không đổi logic phân tích, luật chấm điểm hay cấu trúc bảng. Chỉ sửa đóng gói và cách tìm file.
- Chạy `python -m ruff check src` (nếu đã có) và `python -m pytest -q`; tất cả PASS.
- Cập nhật `CHANGELOG.md` mục "Sửa lỗi đóng gói: thiếu schema.sql" và tăng số phiên bản bản vá theo CHANGELOG hiện tại.
- **Không bịa:** nếu không thể build/chạy `.exe` ở môi trường của bạn, ghi rõ "chưa kiểm chứng trên .exe thật" và liệt kê bước người dùng cần làm.

### 5. BÁO CÁO (tiếng Việt)

1. File đã sửa và nội dung thay đổi.
2. Danh sách file dữ liệu khác đã rà soát và kết quả.
3. Kết quả `pytest`/`ruff` và kết quả bước kiểm tra trong GitHub Actions.
4. Điểm chưa kiểm chứng trên `.exe` thật.

---

## PHỤ LỤC — Người dùng tự kiểm tra sau khi có bản build mới

1. Tải bản `DumpAnalyzer-windows-x64.zip` mới, giải nén vào thư mục mới (không đè lên thư mục cũ).
2. Tìm file `schema.sql` trong thư mục vừa giải nén (thường nằm trong `_internal\dumpanalyzer\storage\`).
3. Mở chương trình, chọn "Máy cục bộ này" và chạy phân tích hệ thống; không còn báo thiếu `schema.sql`.
