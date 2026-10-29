"""
Kiểm thử giao diện dòng lệnh CLI của DumpAnalyzer.
"""

import pytest
from dumpanalyzer.cli import main
from dumpanalyzer import __version__


def test_cli_version(capsys):
    """Kiểm tra gọi tham số --version."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"DumpAnalyzer v{__version__}" in captured.out or f"DumpAnalyzer v{__version__}" in captured.err


def test_cli_check_env(capsys):
    """Kiểm tra lệnh check-env thực thi thành công trả về code 0."""
    ret = main(["check-env"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ĐANG KIỂM TRA MÔI TRƯỜNG HỆ THỐNG" in captured.out
    assert "Cơ sở dữ liệu mã Bug Check:" in captured.out


def test_cli_batch(tmp_path, capsys):
    """Kiểm tra lệnh batch trên thư mục rỗng trả về code 0."""
    folder = tmp_path / "batch_folder"
    folder.mkdir()
    ret = main(["batch", "--dir", str(folder)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "PHÂN TÍCH THEO LÔ ĐA MÁY TÍNH" in captured.out
    assert "Tổng số máy tính nhận diện: 0" in captured.out


def test_cli_clean_workspace(tmp_path, capsys):
    """Kiểm tra lệnh clean-workspace thực thi thành công trả về code 0."""
    ws = tmp_path / "test_ws"
    ws.mkdir()
    d = ws / "test.dmp"
    d.write_bytes(b"DUMP")

    ret = main(["clean-workspace", "--dir", str(ws)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "DỌN DẸP AN TOÀN THƯ MỤC LÀM VIỆC" in captured.out
    assert "Đã xoá an toàn 1 file dump tạm" in captured.out
    assert not d.exists()

