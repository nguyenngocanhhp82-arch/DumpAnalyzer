"""Bộ kiểm thử cho pipeline phân tích sự cố tập trung (run_analysis).

Bảo đảm toàn bộ quy trình đầu-cuối hoạt động chính xác cho cả nguồn 'folder' và 'local',
hỗ trợ bộ nhớ cache, huỷ an toàn và không gây lỗi khi không có dump.
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from dumpanalyzer.core.models import MachineInfo
from dumpanalyzer.engine.pipeline import run_analysis
from dumpanalyzer.engine.scorer import score_machine_crashes
from dumpanalyzer.engine.verdict import generate_machine_finding
from dumpanalyzer.storage.db import Database


@pytest.fixture
def fixtures_dir():
    return Path(__file__).resolve().parent / "fixtures"


def test_pipeline_folder_source_end_to_end(tmp_path, fixtures_dir):
    """Kiểm tra pipeline đầu-cuối với nguồn dữ liệu 'folder'."""
    db_file = tmp_path / "test_pipe_folder.db"
    progress_history = []
    status_history = []

    res = run_analysis(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(db_file),
        progress_cb=lambda pct, msg: progress_history.append((pct, msg)),
        status_cb=lambda msg: status_history.append(msg),
    )

    assert res is not None
    assert len(res["crashes"]) >= 4
    assert res["finding"] is not None
    assert len(res["suspect_ranking"]) > 0
    assert "conflict_detected" in res
    assert "patterns_matched" in res
    assert getattr(res["finding"], "suspect_ranking") == res["suspect_ranking"]

    # Kiểm tra callback tiến trình được gọi tăng dần
    assert len(progress_history) > 0
    assert progress_history[-1][0] == 100
    assert any("Tìm thấy" in msg for msg in status_history)

    # Kiểm tra dữ liệu được lưu vào CSDL
    with Database(str(db_file)) as db:
        crashes_in_db = db.list_crashes()
        assert len(crashes_in_db) >= 4
        findings_in_db = db.get_findings_by_machine(res["finding"].machine_id)
        assert len(findings_in_db) >= 1

    # Chạy lần 2 trên cùng CSDL: kích hoạt cơ chế cache SHA256
    progress_history_2 = []
    res_2 = run_analysis(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(db_file),
        progress_cb=lambda pct, msg: progress_history_2.append((pct, msg)),
    )
    assert res_2 is not None
    assert len(res_2["crashes"]) == len(res["crashes"])
    assert res_2["finding"].suspect == res["finding"].suspect
    assert res_2["finding"].score == res["finding"].score


def test_pipeline_local_source_with_mocks(tmp_path, fixtures_dir):
    """Kiểm tra pipeline nguồn 'local' kết hợp mock Event Log và Windows Update."""
    db_file = tmp_path / "test_pipe_local.db"

    mock_machine = MachineInfo(
        hostname="DESKTOP-TEST",
        model="Test Hardware",
        cpu="Intel Core i7",
        bios="v1.0",
        os_build="19045",
    )

    mock_events = [
        {
            "event_id": 41,
            "provider": "Microsoft-Windows-Kernel-Power",
            "time_created_utc": "2026-10-20T10:00:00Z",
            "level": 1,
            "raw_message": "Kernel-Power event 41",
            "kp41_info": {"is_bsod": True, "bugcheck_code": "0x124"},
        }
    ]

    mock_updates = [
        {
            "hotfix_id": "KB5001234",
            "installed_on": "2026-10-18",
            "description": "Security Update",
        }
    ]

    with patch("dumpanalyzer.engine.pipeline.collect_machine_info", return_value=mock_machine), \
         patch("dumpanalyzer.engine.pipeline.read_system_events", return_value=mock_events), \
         patch("dumpanalyzer.engine.pipeline.collect_recent_windows_updates", return_value=mock_updates), \
         patch("dumpanalyzer.engine.pipeline.load_settings") as mock_set:

        mock_set.return_value = {
            "default_dump_paths": [str(fixtures_dir)],
            "workspace_dir": str(tmp_path / "workspace"),
            "time_window_minutes": 15,
        }

        res = run_analysis(
            source_type="local",
            db_path=str(db_file),
        )

        assert res is not None
        assert res["machine_info"].hostname == "DESKTOP-TEST"
        assert len(res["crashes"]) >= 4
        assert res["finding"] is not None
        assert len(res["evidences"]) > 0


def test_pipeline_zero_dumps_graceful(tmp_path):
    """Kiểm tra trường hợp thư mục rỗng/không có dump: không báo lỗi, kết quả 'không đủ dữ kiện'."""
    empty_folder = tmp_path / "empty_dumps"
    empty_folder.mkdir()
    db_file = tmp_path / "test_pipe_empty.db"

    res = run_analysis(
        source_type="folder",
        folder_path=str(empty_folder),
        db_path=str(db_file),
    )

    assert res is not None
    assert len(res["crashes"]) == 0
    assert res["finding"] is not None
    assert res["finding"].confidence == "không đủ dữ kiện"
    assert "Không tìm thấy file dump" in res["finding"].rationale


def test_pipeline_cancellation(tmp_path, fixtures_dir):
    """Kiểm tra huỷ an toàn giữa chừng: trả về None và đóng CSDL sạch sẽ."""
    db_file = tmp_path / "test_pipe_cancel.db"

    cancelled_flag = [False]

    def check_cancel():
        return cancelled_flag[0]

    def on_progress(pct, msg):
        if pct >= 20:
            cancelled_flag[0] = True

    res = run_analysis(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(db_file),
        progress_cb=on_progress,
        is_cancelled=check_cancel,
    )

    assert res is None

    # Xác nhận CSDL đã được đóng sạch sẽ, có thể mở lại bình thường
    with Database(str(db_file)) as db:
        tables = db._get_connection().execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        assert len(tables) > 0


def test_gui_and_cli_findings_identical(tmp_path, fixtures_dir):
    """Đảm bảo kết luận do GUI (pipeline) và CLI sinh ra từ cùng bộ dữ liệu là hoàn toàn TRÙNG NHAU."""
    db_file = tmp_path / "test_compare.db"

    # 1. Chạy qua pipeline (GUI dùng hàm này)
    gui_res = run_analysis(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(db_file),
    )
    assert gui_res is not None
    gui_finding = gui_res["finding"]

    # 2. Chạy tính toán theo cách CLI tính
    from dumpanalyzer.core.config import get_settings_path, load_settings
    from dumpanalyzer.engine.rule_loader import load_all_rules

    rules = load_all_rules()
    settings = load_settings(get_settings_path())

    crashes_with_evs = [(c, [ev for ev in gui_res["evidences"] if ev.crash_id == c.id]) for c in gui_res["crashes"]]
    scored_cli = score_machine_crashes(crashes_with_evs, rules, settings)
    cli_finding = generate_machine_finding(gui_finding.machine_id, scored_cli, rules)

    # 3. Đối chiếu các trường kết luận quan trọng
    assert gui_finding.suspect == cli_finding.suspect
    assert abs(gui_finding.score - cli_finding.score) < 0.001
    assert gui_finding.confidence == cli_finding.confidence
    ranking_tuples = [(item["suspect"], item["score"]) for item in gui_res["suspect_ranking"]]
    assert ranking_tuples == scored_cli.get("suspect_scores", [])
