# ĐỢT CẬP NHẬT 03 — SỬA LỖI BUILD GITHUB ACTIONS (v1.0.1)

> Dán toàn bộ nội dung từ mục "PROMPT" vào Antigravity. Đợt này chỉ sửa lỗi CI, không đụng logic phân tích.

---

## PROMPT

Bạn đang làm việc trên dự án **DumpAnalyzer**. Sau Đợt 02, workflow GitHub Actions bị lỗi ở bước kiểm tra lint. Hãy sửa theo yêu cầu dưới đây.

### 1. LỖI GHI NHẬN TỪ GITHUB ACTIONS

Job `build-windows` (runner `windows-latest`, shell PowerShell) báo lỗi ở bước chạy lint:

```
Run ruff check src --select F
ruff: D:\a\_temp\bb347100-219b-4ffe-a4f4-24a82dc523c6.ps1:2
Line |
   2 |  ruff check src --select F
     |  ~~~~
     | The term 'ruff' is not recognized as a name of a cmdlet, function, script file, or executable program.
Error: Process completed with exit code 1.
```

### 2. NGUYÊN NHÂN (đã đối chiếu với `pyproject.toml` và `.github/workflows/build.yml` ở v1.0.0)

- Bước "Install Dependencies" cài bằng `pip install -e .[gui,report,dev]`.
- Nhóm phụ thuộc `dev` trong `pyproject.toml` hiện chỉ có `pytest` và `pyinstaller`, **không có `ruff`**.
- Vì vậy runner không có lệnh `ruff`. Lỗi nằm ở cấu hình CI, không phải ở mã nguồn.

> Lưu ý: hãy mở file thực tế hiện tại trong repo để xác nhận. Tôi chỉ đã xem bản v1.0.0, chưa thấy các thay đổi của Đợt 02.

### 3. VIỆC CẦN LÀM

**3.1. Thêm `ruff` vào nhóm `dev` trong `pyproject.toml`**

```toml
dev = [
    "pytest>=7.0.0",
    "pyinstaller>=6.0.0",
    "ruff>=0.5.0",
]
```

Thêm cấu hình ruff để kết quả giống nhau giữa máy dev và CI:

```toml
[tool.ruff]
target-version = "py311"
line-length = 120

[tool.ruff.lint]
select = ["F"]
```

**3.2. Sửa `.github/workflows/build.yml`**

- Đặt bước lint **sau** "Install Dependencies" và **trước** "Run Pytest Suite".
- Gọi qua `python -m ruff` để không phụ thuộc vào PATH của runner:

```yaml
      - name: Lint (ruff - kiểm tra tên chưa định nghĩa, import thừa)
        run: |
          python -m ruff check src
```

- Nếu bước "Install Dependencies" không hề cài từ `pyproject.toml` (ví dụ bạn đã đổi sang `requirements*.txt`), hãy bảo đảm `ruff` được cài ở đúng nơi đó.
- KHÔNG dùng `--exit-zero`, `|| true`, `continue-on-error: true` hay bất kỳ cách nào khác để che lỗi lint.

**3.3. Nếu sau khi cài được ruff mà nó báo lỗi thật trong `src/`**

- Sửa từng lỗi trong mã nguồn (tên chưa định nghĩa, import thừa, biến không dùng...). Đây chính là mục đích của bước lint.
- Không tắt luật (`ignore`) chỉ để cho qua. Nếu thật sự cần bỏ qua một dòng, dùng `# noqa: <mã>` kèm chú thích lý do.
- Mỗi nhóm lỗi sửa trong một commit riêng.

**3.4. Chạy thử cục bộ trước khi đẩy lên**

```bash
pip install -e ".[gui,report,dev]"
python -m ruff check src
python -m pytest -q
```

Trên Windows PowerShell, các lệnh giống hệt. Dán kết quả vào báo cáo.

### 4. NGUYÊN TẮC

1. Tạo nhánh `fix/ci-ruff` từ `main`, mở pull request để GitHub tự chạy workflow trước khi gộp.
2. Không đổi các bước build/đóng gói PyInstaller và bước phát hành Release.
3. Không đổi phiên bản trong `pyproject.toml` ngoài việc tăng lên `1.0.1` nếu Đợt 02 chưa làm. Cập nhật `CHANGELOG.md` mục "Sửa lỗi CI".
4. Không bịa kết quả. Nếu không chạy được workflow trên GitHub từ môi trường của bạn, ghi rõ "chưa xác nhận trên GitHub Actions" và liệt kê việc người dùng cần làm.

### 5. TIÊU CHÍ HOÀN THÀNH

- Workflow `Build & Release DumpAnalyzer` chạy **xanh** toàn bộ các bước: Install → Lint → Pytest → Build → Upload.
- `python -m ruff check src` trả về "All checks passed!" khi chạy cục bộ.
- `pytest` vẫn PASS toàn bộ.

### 6. ĐỊNH DẠNG BÁO CÁO (tiếng Việt)

1. File đã sửa và nội dung thay đổi.
2. Kết quả chạy cục bộ: `ruff` và `pytest`.
3. Danh sách lỗi lint thật đã phát hiện và sửa (nếu có).
4. Việc chưa xác nhận được và lệnh/bước để người dùng tự kiểm tra.

---

## PHỤ LỤC — Người dùng tự kiểm tra sau khi Antigravity xong

1. Mở trang Actions của repo trên GitHub, mở lần chạy mới nhất, xác nhận cả bước "Lint" và "Run Pytest Suite" đều có dấu xanh.
2. Tải artifact `DumpAnalyzer-windows-x64` và chạy thử file `.exe` trên một máy Windows.
