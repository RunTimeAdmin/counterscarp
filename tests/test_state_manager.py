"""Tests for state_manager.py — ScanStateManager."""

import json
import os
import sys
import time
from pathlib import Path

import pytest

# Ensure project root is importable
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from state_manager import ScanStateManager, StateError, _CounterscarpJSONEncoder


# ===========================================================================
# TestCounterscarpJSONEncoder
# ===========================================================================

class TestCounterscarpJSONEncoder:
    """Tests for the custom JSON encoder."""

    def test_encodes_path(self):
        data = {"p": Path("/some/path")}
        result = json.dumps(data, cls=_CounterscarpJSONEncoder)
        # Path is serialised as a string; separator is platform-dependent
        assert "some" in result and "path" in result

    def test_encodes_set(self):
        data = {"s": {1, 2, 3}}
        result = json.dumps(data, cls=_CounterscarpJSONEncoder)
        parsed = json.loads(result)
        assert set(parsed["s"]) == {1, 2, 3}

    def test_encodes_datetime(self):
        from datetime import datetime, timezone
        dt = datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc)
        data = {"dt": dt}
        result = json.dumps(data, cls=_CounterscarpJSONEncoder)
        assert "2026-04-21" in result

    def test_encodes_dataclass(self):
        import dataclasses

        @dataclasses.dataclass
        class Foo:
            x: int
            y: str

        data = {"obj": Foo(x=1, y="hello")}
        result = json.dumps(data, cls=_CounterscarpJSONEncoder)
        parsed = json.loads(result)
        assert parsed["obj"]["x"] == 1
        assert parsed["obj"]["y"] == "hello"

    def test_raises_for_unknown_type(self):
        class Unserializable:
            pass

        with pytest.raises(TypeError):
            json.dumps({"obj": Unserializable()}, cls=_CounterscarpJSONEncoder)


# ===========================================================================
# TestScanStateManagerStartSession
# ===========================================================================

class TestScanStateManagerStartSession:
    """Tests for ScanStateManager.start_session()."""

    def test_start_session_returns_session_id(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/tmp/contract.sol", {"report": True})
        assert isinstance(sid, str)
        assert len(sid) > 8

    def test_start_session_creates_state_file(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/tmp/contract.sol", {})
        state_file = tmp_path / f"scan_state_{sid}.json"
        assert state_file.exists()

    def test_start_session_file_contains_expected_fields(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/tmp/contract.sol", {"flag": True})
        state_file = tmp_path / f"scan_state_{sid}.json"
        data = json.loads(state_file.read_text())
        assert data["session_id"] == sid
        assert data["target"] == "/tmp/contract.sol"
        assert data["status"] == "in_progress"
        assert data["phases_completed"] == []
        assert "started_at" in data

    def test_start_session_unique_ids(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid1 = sm.start_session("/a.sol", {})
        sid2 = sm.start_session("/b.sol", {})
        assert sid1 != sid2

    def test_start_session_creates_counterscarp_dir(self, tmp_path):
        new_dir = tmp_path / "nested" / "dir"
        sm = ScanStateManager(counterscarp_dir=str(new_dir))
        sm.start_session("/c.sol", {})
        assert new_dir.exists()


# ===========================================================================
# TestMarkPhaseComplete
# ===========================================================================

class TestMarkPhaseComplete:
    """Tests for mark_phase_complete()."""

    def test_mark_phase_complete_adds_entry(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/test.sol", {})
        sm.mark_phase_complete("slither", findings_count=5, duration_secs=12.3)
        phases = sm.get_completed_phases()
        assert "slither" in phases

    def test_mark_multiple_phases(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/test.sol", {})
        sm.mark_phase_complete("slither")
        sm.mark_phase_complete("heuristic")
        sm.mark_phase_complete("sarif")
        phases = sm.get_completed_phases()
        assert phases == {"slither", "heuristic", "sarif"}

    def test_mark_phase_without_session_raises(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.mark_phase_complete("slither")

    def test_phase_entry_has_metadata(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/test.sol", {})
        sm.mark_phase_complete("slither", findings_count=7, duration_secs=3.5)
        state_file = tmp_path / f"scan_state_{sid}.json"
        data = json.loads(state_file.read_text())
        phase = data["phases_completed"][0]
        assert phase["name"] == "slither"
        assert phase["findings_count"] == 7
        assert phase["duration_secs"] == 3.5


# ===========================================================================
# TestGetCompletedPhases
# ===========================================================================

class TestGetCompletedPhases:
    """Tests for get_completed_phases()."""

    def test_empty_phases_initially(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        phases = sm.get_completed_phases()
        assert phases == set()

    def test_raises_without_session(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.get_completed_phases()

    def test_phases_returned_as_set(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        sm.mark_phase_complete("pha")
        result = sm.get_completed_phases()
        assert isinstance(result, set)


# ===========================================================================
# TestIsPhasePending
# ===========================================================================

class TestIsPhasePending:
    """Tests for is_phase_pending()."""

    def test_unrun_phase_is_pending(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        assert sm.is_phase_pending("slither") is True

    def test_completed_phase_not_pending(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        sm.mark_phase_complete("slither")
        assert sm.is_phase_pending("slither") is False

    def test_other_phase_still_pending_after_one_done(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        sm.mark_phase_complete("slither")
        assert sm.is_phase_pending("heuristic") is True


# ===========================================================================
# TestSaveLoadPhaseResults
# ===========================================================================

class TestSaveLoadPhaseResults:
    """Tests for save_phase_results() and load_phase_results()."""

    def test_save_and_load_dict_results(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        data = {"findings": [{"id": 1, "severity": "HIGH"}], "count": 1}
        sm.save_phase_results("slither", data)
        loaded = sm.load_phase_results("slither")
        assert loaded == data

    def test_save_and_load_list_results(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        data = [1, 2, 3, "hello"]
        sm.save_phase_results("heuristic", data)
        loaded = sm.load_phase_results("heuristic")
        assert loaded == data

    def test_load_missing_phase_returns_none(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm.start_session("/t.sol", {})
        result = sm.load_phase_results("nonexistent_phase")
        assert result is None

    def test_save_phase_without_session_raises(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.save_phase_results("slither", {})

    def test_load_phase_without_session_raises(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.load_phase_results("slither")

    def test_phase_results_file_created(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/t.sol", {})
        sm.save_phase_results("sarif", {"output": "ok"})
        result_file = tmp_path / f"phase_sarif_{sid}.json"
        assert result_file.exists()


# ===========================================================================
# TestMarkSessionComplete
# ===========================================================================

class TestMarkSessionComplete:
    """Tests for mark_session_complete()."""

    def test_mark_complete_sets_status(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/t.sol", {})
        sm.mark_session_complete()
        state_file = tmp_path / f"scan_state_{sid}.json"
        data = json.loads(state_file.read_text())
        assert data["status"] == "completed"
        assert "completed_at" in data

    def test_mark_complete_without_session_raises(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.mark_session_complete()


# ===========================================================================
# TestLoadSession
# ===========================================================================

class TestLoadSession:
    """Tests for load_session()."""

    def test_load_existing_session(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/t.sol", {"key": "val"})
        sm.mark_phase_complete("slither", 3)

        sm2 = ScanStateManager(counterscarp_dir=str(tmp_path))
        state = sm2.load_session(sid)

        assert state["session_id"] == sid
        assert state["target"] == "/t.sol"
        assert len(state["phases_completed"]) == 1

    def test_load_session_makes_it_active(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/t.sol", {})

        sm2 = ScanStateManager(counterscarp_dir=str(tmp_path))
        sm2.load_session(sid)
        # After load, we should be able to use it
        phases = sm2.get_completed_phases()
        assert isinstance(phases, set)

    def test_load_nonexistent_session_raises(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(FileNotFoundError):
            sm.load_session("nonexistent_session_id")

    def test_load_corrupt_session_raises_state_error(self, tmp_path):
        corrupt_file = tmp_path / "scan_state_corrupt_id.json"
        corrupt_file.write_text("{invalid json{{", encoding="utf-8")
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        with pytest.raises(StateError):
            sm.load_session("corrupt_id")


# ===========================================================================
# TestCleanupOldSessions
# ===========================================================================

class TestCleanupOldSessions:
    """Tests for cleanup_old_sessions()."""

    def test_cleanup_removes_old_files(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        # Create a fake old state file
        old_file = tmp_path / "scan_state_old_session.json"
        old_file.write_text('{"session_id": "old"}', encoding="utf-8")
        # Set mtime to 40 days ago
        old_time = time.time() - 40 * 86400
        os.utime(str(old_file), (old_time, old_time))

        sm.cleanup_old_sessions(max_age_days=30)
        assert not old_file.exists()

    def test_cleanup_keeps_recent_files(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        sid = sm.start_session("/recent.sol", {})
        state_file = tmp_path / f"scan_state_{sid}.json"

        sm.cleanup_old_sessions(max_age_days=30)
        assert state_file.exists()

    def test_cleanup_removes_old_phase_files(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        old_phase = tmp_path / "phase_slither_old_session.json"
        old_phase.write_text('{"data": []}', encoding="utf-8")
        old_time = time.time() - 60 * 86400
        os.utime(str(old_phase), (old_time, old_time))

        sm.cleanup_old_sessions(max_age_days=30)
        assert not old_phase.exists()

    def test_cleanup_with_no_files(self, tmp_path):
        sm = ScanStateManager(counterscarp_dir=str(tmp_path))
        # Should not raise even when no files match
        sm.cleanup_old_sessions(max_age_days=30)


# ===========================================================================
# TestStateError
# ===========================================================================

class TestStateError:
    """Tests for the StateError exception."""

    def test_state_error_message(self):
        err = StateError("Something went wrong")
        assert "Something went wrong" in str(err)

    def test_state_error_with_details(self):
        err = StateError("Bad state", details={"path": "/tmp/scan.json"})
        assert err is not None

    def test_state_error_is_exception(self):
        with pytest.raises(StateError):
            raise StateError("test error")
