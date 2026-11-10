"""
Kiểm thử tự động cho cơ chế đóng gói và định vị file schema.sql (HOTFIX 01).
Đảm bảo chạy độc lập trên mọi hệ điều hành (kể cả Linux CI) mà không cần bản build .exe thật.
"""

import sys
from pathlib import Path
import pytest

from dumpanalyzer.storage.db import _find_schema_file, Database
from dumpanalyzer.core.config import get_project_root


def test_find_schema_file_source_mode():
    """1. _find_schema_file() tìm được file khi chạy từ mã nguồn."""
    schema_path = _find_schema_file()
    assert isinstance(schema_path, Path)
    assert schema_path.is_file()
    assert schema_path.name == "schema.sql"
    content = schema_path.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS crash" in content


def test_find_schema_file_meipass_frozen_mode(tmp_path, monkeypatch):
    """2. Giả lập chế độ đóng gói: đặt sys._MEIPASS về thư mục tạm, trỏ __file__ tới nơi không có file."""
    # Tạo cấu trúc thư mục giả lập PyInstaller _internal/dumpanalyzer/storage/schema.sql
    pkg_storage = tmp_path / "dumpanalyzer" / "storage"
    pkg_storage.mkdir(parents=True)
    fake_schema = pkg_storage / "schema.sql"
    fake_schema.write_text("-- fake meipass schema", encoding="utf-8")

    # Giả lập sys._MEIPASS
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    # Trỏ __file__ của module db tới thư mục rỗng không có schema.sql
    dummy_db_file = tmp_path / "dummy_module" / "db.py"
    dummy_db_file.parent.mkdir(parents=True)
    import dumpanalyzer.storage.db as db_mod
    monkeypatch.setattr(db_mod, "__file__", str(dummy_db_file))

    found = _find_schema_file()
    assert found == fake_schema
    assert found.read_text(encoding="utf-8") == "-- fake meipass schema"


def test_find_schema_file_meipass_direct_storage_fallback(tmp_path, monkeypatch):
    """2b. Giả lập sys._MEIPASS dạng fallback storage/schema.sql trực tiếp."""
    direct_storage = tmp_path / "storage"
    direct_storage.mkdir(parents=True)
    fake_schema = direct_storage / "schema.sql"
    fake_schema.write_text("-- direct storage schema", encoding="utf-8")

    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    dummy_db_file = tmp_path / "dummy_module" / "db.py"
    dummy_db_file.parent.mkdir(parents=True)
    import dumpanalyzer.storage.db as db_mod
    monkeypatch.setattr(db_mod, "__file__", str(dummy_db_file))

    found = _find_schema_file()
    assert found == fake_schema
    assert found.read_text(encoding="utf-8") == "-- direct storage schema"


def test_find_schema_file_not_found_raises_informative_error(tmp_path, monkeypatch):
    """3. Khi không tìm thấy ở đâu cả -> ném FileNotFoundError có liệt kê đường dẫn đã thử và gợi ý tiếng Việt."""
    empty_meipass = tmp_path / "empty_bundle"
    empty_meipass.mkdir(parents=True)
    monkeypatch.setattr(sys, "_MEIPASS", str(empty_meipass), raising=False)

    dummy_db_file = tmp_path / "nonexistent_dir" / "db.py"
    dummy_db_file.parent.mkdir(parents=True)
    import dumpanalyzer.storage.db as db_mod
    monkeypatch.setattr(db_mod, "__file__", str(dummy_db_file))

    with pytest.raises(FileNotFoundError) as exc_info:
        _find_schema_file()

    err_msg = str(exc_info.value)
    assert "Không tìm thấy schema.sql. Đã thử:" in err_msg
    assert "Gợi ý: bản đóng gói thiếu file dữ liệu" in err_msg
    assert str(empty_meipass) in err_msg
    assert "schema.sql" in err_msg


def test_spec_file_includes_schema_sql_in_both_analyses():
    """4. Đọc DumpAnalyzer.spec và xác nhận schema.sql xuất hiện trong datas của CẢ HAI Analysis."""
    spec_path = get_project_root() / "DumpAnalyzer.spec"
    assert spec_path.is_file(), f"Không tìm thấy spec file tại {spec_path}"
    spec_text = spec_path.read_text(encoding="utf-8")

    # Kiểm tra biến SCHEMA_SQL được định nghĩa
    assert "SCHEMA_SQL" in spec_text
    assert "'schema.sql'" in spec_text or '"schema.sql"' in spec_text

    # Kiểm tra a_gui và a_cli đều cấu hình datas với SCHEMA_SQL
    assert "a_gui = Analysis(" in spec_text
    assert "a_cli = Analysis(" in spec_text

    gui_block = spec_text[spec_text.find("a_gui = Analysis("): spec_text.find("pyz_gui = PYZ(")]
    cli_block = spec_text[spec_text.find("a_cli = Analysis("): spec_text.find("pyz_cli = PYZ(")]

    assert "datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')]" in gui_block or "SCHEMA_SQL" in gui_block
    assert "datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')]" in cli_block or "SCHEMA_SQL" in cli_block
    assert "'dumpanalyzer/storage'" in gui_block
    assert "'dumpanalyzer/storage'" in cli_block


def test_pyproject_toml_declares_package_data():
    """5. Đọc pyproject.toml và xác nhận có khai báo package-data cho schema.sql."""
    pyproject_path = get_project_root() / "pyproject.toml"
    assert pyproject_path.is_file(), f"Không tìm thấy pyproject.toml tại {pyproject_path}"
    pyproject_text = pyproject_path.read_text(encoding="utf-8")

    assert "[tool.setuptools.package-data]" in pyproject_text
    assert 'dumpanalyzer = ["storage/schema.sql"]' in pyproject_text or "storage/schema.sql" in pyproject_text


def test_database_init_succeeds_with_resolved_schema(tmp_path):
    """6. Kiểm tra Database khởi tạo bảng thành công từ schema tìm được."""
    db_file = tmp_path / "test_init.db"
    db = Database(db_path=db_file)
    conn = db._get_connection()
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cur.fetchall()}

    expected_tables = {"crash", "evidence", "finding", "feedback", "asset_info"}
    for tbl in expected_tables:
        assert tbl in tables, f"Thiếu bảng {tbl} sau khi khởi tạo CSDL"

    db.close()


def test_spec_file_includes_portable_target():
    """7. Kiểm tra DumpAnalyzer.spec có cấu hình Analysis và EXE cho bản Portable 1 file duy nhất."""
    spec_path = get_project_root() / "DumpAnalyzer.spec"
    assert spec_path.is_file(), f"Không tìm thấy spec file tại {spec_path}"
    spec_text = spec_path.read_text(encoding="utf-8")

    # Kiểm tra target a_portable và exe_portable
    assert "a_portable = Analysis(" in spec_text
    assert "exe_portable = EXE(" in spec_text
    assert "name='DumpAnalyzer-Portable'" in spec_text or 'name="DumpAnalyzer-Portable"' in spec_text

    # Kiểm tra datas của a_portable chứa cả SCHEMA_SQL và CONFIG_DIR
    portable_block = spec_text[spec_text.find("a_portable = Analysis("): spec_text.find("pyz_portable = PYZ(")]
    assert "SCHEMA_SQL" in portable_block
    assert "CONFIG_DIR" in portable_block
    assert "'config'" in portable_block or '"config"' in portable_block


def test_get_config_dir_resolution(tmp_path, monkeypatch):
    """8. Kiểm tra get_config_dir() ưu tiên config ngoài, fallback _MEIPASS, hoặc dev root."""
    from dumpanalyzer.core.config import get_config_dir

    # Trường hợp 1: Chế độ dev thông thường -> trả về config/ của dự án
    dev_cfg = get_config_dir()
    assert dev_cfg.is_dir()
    assert (dev_cfg / "settings.yaml").is_file()

    # Trường hợp 2: Chế độ frozen có config/ bên cạnh file thực thi
    fake_exe_dir = tmp_path / "bin"
    fake_exe_dir.mkdir()
    fake_exe = fake_exe_dir / "DumpAnalyzer-Portable.exe"
    fake_exe.touch()
    external_cfg = fake_exe_dir / "config"
    external_cfg.mkdir()
    (external_cfg / "settings.yaml").write_text("external: true", encoding="utf-8")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe), raising=False)

    resolved = get_config_dir()
    assert resolved == external_cfg
    assert (resolved / "settings.yaml").read_text(encoding="utf-8") == "external: true"

    # Trường hợp 3: Chế độ frozen không có config/ ngoài, fallback _MEIPASS/config
    import shutil
    shutil.rmtree(external_cfg)
    meipass_dir = tmp_path / "meipass_extracted"
    meipass_cfg = meipass_dir / "config"
    meipass_cfg.mkdir(parents=True)
    (meipass_cfg / "settings.yaml").write_text("bundled: true", encoding="utf-8")

    monkeypatch.setattr(sys, "_MEIPASS", str(meipass_dir), raising=False)

    resolved_bundle = get_config_dir()
    assert resolved_bundle == meipass_cfg
    assert (resolved_bundle / "settings.yaml").read_text(encoding="utf-8") == "bundled: true"


def test_main_portable_cli_dispatch(monkeypatch):
    """9. main_portable.py gọi CLI khi có tham số dòng lệnh."""
    from dumpanalyzer import main_portable

    cli_called = []

    def mock_cli_main(args):
        cli_called.append(args)
        return 123

    monkeypatch.setattr("dumpanalyzer.cli.main", mock_cli_main)
    monkeypatch.setattr(sys, "argv", ["DumpAnalyzer-Portable", "scan", "C:\\dumps"])

    ret = main_portable.main()
    assert ret == 123
    assert cli_called == [["scan", "C:\\dumps"]]


def test_main_portable_gui_dispatch(monkeypatch):
    """10. main_portable.py gọi GUI khi không có tham số hoặc có --gui / -g."""
    from dumpanalyzer import main_portable

    gui_called = []

    def mock_gui_main():
        gui_called.append(True)
        return 0

    monkeypatch.setattr("dumpanalyzer.gui.app.main", mock_gui_main)

    # Khi không có tham số
    monkeypatch.setattr(sys, "argv", ["DumpAnalyzer-Portable"])
    ret = main_portable.main()
    assert ret == 0
    assert len(gui_called) == 1

    # Khi có tham số --gui
    monkeypatch.setattr(sys, "argv", ["DumpAnalyzer-Portable", "--gui"])
    ret_gui = main_portable.main()
    assert ret_gui == 0
    assert len(gui_called) == 2

    # Khi có tham số -g
    monkeypatch.setattr(sys, "argv", ["DumpAnalyzer-Portable", "-g"])
    ret_g = main_portable.main()
    assert ret_g == 0
    assert len(gui_called) == 3
