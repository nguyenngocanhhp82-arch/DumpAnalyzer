---
name: python-windows-ci-guard
description: >-
  Kích hoạt kỹ năng này khi phát triển, cấu hình hoặc sửa lỗi CI/CD GitHub Actions cho các dự án Python chạy trên Windows runner (windows-latest). Ngăn ngừa triệt để lỗi 'The term is not recognized' (ruff, pytest, pyinstaller) do PATH/thiếu dev dependency và lỗi UnicodeEncodeError cp1252 khi in thông điệp tiếng Việt.
---

# Python Windows CI & GitHub Actions Guard

## 1. Triệu chứng sự cố (Symptoms)

Khi đẩy mã nguồn lên GitHub Actions có job chạy trên runner Windows (`windows-latest`, shell PowerShell):

### Triệu chứng 1: Không tìm thấy công cụ CLI (Missing Tool / PATH Issue)
```text
Run ruff check src --select F
ruff: D:\a\_temp\bb347100-219b-4ffe-a4f4-24a82dc523c6.ps1:2
Line |
   2 |  ruff check src --select F
     |  ~~~~
     | The term 'ruff' is not recognized as a name of a cmdlet, function, script file, or executable program.
Error: Process completed with exit code 1.
```

### Triệu chứng 2: Lỗi bảng mã console Windows cp1252 (UnicodeEncodeError)
```text
Run python build_exe.py
Traceback (most recent call last):
  File "D:\a\...\build_exe.py", line 24, in build
    print("      TIẾN HÀNH ĐÓNG GÓI DUMPANALYZER (PYINSTALLER)")
  File "C:\...\Lib\encodings\cp1252.py", line 19, in encode
    return codecs.charmap_encode(input,self.errors,encoding_table)[0]
UnicodeEncodeError: 'charmap' codec can't encode character '\u1ebe' in position 8: character maps to <undefined>
Error: Process completed with exit code 1.
```

---

## 2. Nguyên nhân cốt lõi (Root Cause)

1. **Thiếu phụ thuộc trong `pyproject.toml` hoặc PATH của PowerShell**:
   - Khi workflow cài đặt bằng `pip install -e .[gui,report,dev]`, nếu công cụ (như `ruff`, `flake8`) không được khai báo trong nhóm `[project.optional-dependencies] dev`, runner sẽ không có công cụ đó.
   - Thậm chí khi đã cài đặt, thư mục `Scripts\` của Python trên Windows đôi khi không nằm trong `PATH` mặc định của phiên PowerShell chạy script, khiến lệnh gọi trực tiếp `ruff check ...` bị báo lỗi cmdlet.

2. **Bảng mã mặc định của Windows Console là `cp1252`**:
   - Môi trường Windows runner sử dụng bảng mã phương Tây `cp1252` cho stdout/stderr nếu không được chỉ định khác.
   - Khi bất kỳ script Python nào in ra màn hình các ký tự Unicode có dấu (tiếng Việt như `ế`, `ộ`, `Đ`...), hàm `print()` của Python sẽ văng lỗi `UnicodeEncodeError` ngay lập tức.

---

## 3. Quy tắc bắt buộc khi cấu hình Python trên Windows CI (Golden Rules)

### QUY TẮC 1: Luôn khai báo đầy đủ công cụ trong `pyproject.toml`
Khi thêm bất kỳ bước kiểm tra nào trong CI (ví dụ lint bằng `ruff`), **BẮT BUỘC** phải khai báo công cụ đó vào nhóm `dev`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pyinstaller>=6.0.0",
    "ruff>=0.5.0",
]

[tool.ruff]
target-version = "py311"
line-length = 120

[tool.ruff.lint]
select = ["F"]
```

### QUY TẮC 2: Luôn gọi công cụ CLI qua `python -m <module>`
Trong file workflow GitHub Actions (`.github/workflows/*.yml`), **KHÔNG BAO GIỜ** gọi thẳng tên binary (`ruff`, `pytest`, `pyinstaller`). **LUÔN LUÔN** gọi qua `python -m`:

```yaml
# SAI: Dễ bị lỗi "The term 'ruff' is not recognized" trên PowerShell
- name: Run Ruff
  run: ruff check src

# ĐÚNG: Chạy trực tiếp qua Python executable trong PATH của runner
- name: Lint (ruff)
  run: |
    python -m ruff check src

- name: Run Pytest
  run: |
    python -m pytest -v
```

### QUY TẮC 3: Thiết lập môi trường UTF-8 toàn diện trong GitHub Actions
Thêm biến môi trường `PYTHONIOENCODING` và `PYTHONUTF8` vào cấp độ `env` của job:

```yaml
jobs:
  build-windows:
    name: Build Windows Executable (.exe)
    runs-on: windows-latest
    env:
      PYTHONIOENCODING: "utf-8"
      PYTHONUTF8: "1"
```

### QUY TẮC 4: Tự bảo vệ trong script Python (Defensive Python Scripting)
Đối với các script tự động hoá đóng gói (như `build_exe.py`), luôn thêm 2 lớp bảo vệ:

1. **Reconfigure stream ở đầu file**:
   ```python
   import sys
   if sys.stdout and hasattr(sys.stdout, "reconfigure"):
       try:
           sys.stdout.reconfigure(encoding="utf-8", errors="replace")
       except Exception:
           pass
   if sys.stderr and hasattr(sys.stderr, "reconfigure"):
       try:
           sys.stderr.reconfigure(encoding="utf-8", errors="replace")
       except Exception:
           pass
   ```
2. **Dùng chuỗi không dấu (ASCII-Safe) cho log console của script**:
   - In ra console: `TIEN HANH DONG GOI`, `Dang sao chep`, `Thanh cong`...
   - File tài liệu ghi xuống đĩa: dùng `write_text(..., encoding="utf-8")` để lưu trữ tiếng Việt có dấu an toàn.
