"""
Kiểm thử cdb_runner: xây dựng tham số lệnh, extra commands theo mã lỗi,
fallback về header_only khi thiếu cdb và lệnh CLI analyze, warmup-symbols.
"""

from pathlib import Path
from dumpanalyzer.analyzer.cdb_runner import (
    build_cdb_command_args,
    get_extra_cdb_commands,
    analyze_dump_file,
)
from dumpanalyzer.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_build_cdb_command_args():
    """Kiểm tra xây dựng danh sách đối số an toàn cho cdb.exe."""
    args = build_cdb_command_args(
        dump_path="C:\\dumps\\test.dmp",
        cdb_exe="C:\\Debuggers\\cdb.exe",
        symbol_path="srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
        extra_commands=["!errrec ffff800012345678"],
        logo_file="C:\\dumps\\out.txt",
    )

    assert isinstance(args, list)
    assert args[0] == "C:\\Debuggers\\cdb.exe"
    assert args[1] == "-z"
    assert args[2] == "C:\\dumps\\test.dmp"
    assert args[3] == "-y"
    assert "-c" in args

    # Kiểm tra chuỗi lệnh có chứa extra_command và kết thúc bằng 'q'
    c_idx = args.index("-c") + 1
    script = args[c_idx]
    assert "!errrec ffff800012345678" in script
    assert script.endswith("; q") or script.endswith("q")
    assert "-logo" in args


def test_get_extra_cdb_commands():
    """Kiểm tra sinh lệnh cdb chuyên sâu theo mã lỗi từ bugcheck_rules.yaml."""
    # 0x124 -> !errrec {p2}
    extra_124 = get_extra_cdb_commands("0x124", {"p2": "ffff800012345678"})
    assert any("!errrec ffff800012345678" in cmd for cmd in extra_124)

    # 0x133 -> !dpcs, !timer
    extra_133 = get_extra_cdb_commands("0x133")
    assert any("!dpcs" in cmd for cmd in extra_133)
    assert any("!timer" in cmd for cmd in extra_133)

    # 0x1A -> !vm, !poolused 2
    extra_1a = get_extra_cdb_commands("0x1A")
    assert any("!vm" in cmd for cmd in extra_1a)


def test_analyze_dump_file_fallback_without_cdb():
    """
    Khi môi trường không có cdb.exe (hoặc file mock),
    hệ thống phải fallback về header_only một cách mượt mà không crash.
    """
    sample_dump = FIXTURES_DIR / "kernel_sample_124.dmp"
    res = analyze_dump_file(sample_dump, cdb_path="/nonexistent/cdb.exe")

    assert res["analyzed_by"] == "header_only"
    assert res["cdb_result"].bugcheck_code == "0x124"
    assert res["cdb_result"].bugcheck_name == "WHEA_UNCORRECTABLE_ERROR"
    assert res["cdb_result"].p2 == "0xFFFF800012345678"


def test_cli_warmup_symbols(capsys):
    """Kiểm tra gọi lệnh CLI warmup-symbols."""
    ret = main(["warmup-symbols"])
    # Trên Linux không có cdb.exe thật, lệnh báo thông tin rõ ràng
    assert ret in (0, 1)
    captured = capsys.readouterr().out
    assert "TẢI TRƯỚC SYMBOLS MICROSOFT" in captured


def test_cli_analyze_command(capsys):
    """Kiểm tra lệnh CLI analyze thực thi và fallback an toàn."""
    sample_dump = FIXTURES_DIR / "kernel_sample_124.dmp"
    ret = main(["analyze", "--path", str(sample_dump)])
    assert ret == 0

    captured = capsys.readouterr().out
    assert "Bắt đầu phân tích chuyên sâu" in captured
    assert "0x124" in captured
    assert "header_only" in captured or "cdb" in captured
