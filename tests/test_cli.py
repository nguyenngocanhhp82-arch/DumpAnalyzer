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
    assert "Môi trường thực thi:" in captured.out
    assert "Cơ sở dữ liệu mã Bug Check:" in captured.out
