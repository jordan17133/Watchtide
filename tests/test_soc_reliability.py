"""Synthetic regression checks: no real Indexer, SQL connection, or SSH session."""

import io
import types
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import requests

from loader import wazuh_to_sql as loader
from warehouse import cases


NOW = datetime(2026, 10, 4, 12)


def indexer_response(status=200, body=None):
    response = requests.Response()
    response.status_code = status
    response.json = Mock(return_value=body)
    indexer = object.__new__(loader.Indexer)
    indexer.url = "https://indexer.example.test"
    indexer.session = Mock()
    indexer.session.post.return_value = response
    return indexer


class TunnelTests(unittest.TestCase):
    settings = {"SSH_TUNNEL_TARGET": "soc-user@soc.example.test",
                "SSH_KEY_FILE": "fixture-key", "SSH_TUNNEL_LOCAL_PORT": "19201"}

    def test_tunnel_pins_loopback_known_host_and_noninteractive_authentication(self):
        process = Mock()
        process.poll.return_value = None
        connection = Mock()
        with patch.object(loader.subprocess, "Popen", return_value=process) as spawn, \
             patch.object(loader.socket, "create_connection", return_value=connection) as connect:
            with loader.ssh_tunnel(self.settings):
                process.terminate.assert_not_called()
            args = spawn.call_args.args[0]
            self.assertEqual(args[args.index("-L") + 1], "127.0.0.1:19201:127.0.0.1:9200")
            for option in ("StrictHostKeyChecking=yes", "GatewayPorts=no", "IdentitiesOnly=yes",
                           "BatchMode=yes", "ExitOnForwardFailure=yes"):
                self.assertIn(option, args)
            self.assertNotIn("StrictHostKeyChecking=accept-new", args)
            self.assertEqual(spawn.call_args.kwargs["stdin"], loader.subprocess.DEVNULL)
            connect.assert_called_once_with(("127.0.0.1", 19201), timeout=1)
            connection.close.assert_called_once()
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)

    def test_default_tunnel_port_is_also_loopback_only(self):
        process = Mock()
        process.poll.return_value = None
        settings = {k: v for k, v in self.settings.items() if k != "SSH_TUNNEL_LOCAL_PORT"}
        with patch.object(loader.subprocess, "Popen", return_value=process) as spawn, \
             patch.object(loader.socket, "create_connection", return_value=Mock()):
            with loader.ssh_tunnel(settings):
                pass
            args = spawn.call_args.args[0]
            self.assertEqual(args[args.index("-L") + 1], "127.0.0.1:19200:127.0.0.1:9200")

    def test_alternate_address_keeps_the_explicit_verified_host_identity(self):
        process = Mock()
        process.poll.return_value = None
        settings = dict(self.settings, SSH_TUNNEL_TARGET="soc-user@192.0.2.20",
                        SSH_TUNNEL_HOST_KEY_ALIAS="soc.example.test")
        with patch.object(loader.subprocess, "Popen", return_value=process) as spawn, \
             patch.object(loader.socket, "create_connection", return_value=Mock()):
            with loader.ssh_tunnel(settings):
                pass
            args = spawn.call_args.args[0]
            self.assertIn("HostKeyAlias=soc.example.test", args)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("ConnectTimeout=10", args)
            self.assertEqual(args[-1], "soc-user@192.0.2.20")

    def test_invalid_identity_alias_stops_before_starting_ssh(self):
        for alias in ("-oStrictHostKeyChecking=no", "soc\nother", "soc example", "a" * 254):
            with self.subTest(alias=alias), patch.object(loader.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    with loader.ssh_tunnel(dict(self.settings, SSH_TUNNEL_HOST_KEY_ALIAS=alias)):
                        pass
                spawn.assert_not_called()

    def test_ssh_refusal_fails_closed_and_cleans_up(self):
        process = Mock()
        process.poll.return_value = 1
        process.stderr.read.return_value = b"Host key verification failed."
        with patch.object(loader.subprocess, "Popen", return_value=process), \
             patch.object(loader.socket, "create_connection") as connect:
            with self.assertRaisesRegex(RuntimeError, "SSH tunnel failed"):
                with loader.ssh_tunnel(self.settings):
                    self.fail("A refused connection must not yield.")
            connect.assert_not_called()
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)

    def test_tunnel_readiness_timeout_cleans_up(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(loader.subprocess, "Popen", return_value=process), \
             patch.object(loader.socket, "create_connection", side_effect=OSError("not ready")), \
             patch.object(loader.time, "monotonic", side_effect=(0, 21)):
            with self.assertRaisesRegex(RuntimeError, "did not open"):
                with loader.ssh_tunnel(self.settings):
                    self.fail("An unopened tunnel must not yield.")
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)

    def test_downstream_failure_also_closes_tunnel(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(loader.subprocess, "Popen", return_value=process), \
             patch.object(loader.socket, "create_connection", return_value=Mock()):
            with self.assertRaisesRegex(ValueError, "downstream"):
                with loader.ssh_tunnel(self.settings):
                    raise ValueError("downstream")
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)

    def test_direct_mode_does_not_spawn_an_ssh_process(self):
        with patch.object(loader.subprocess, "Popen") as spawn:
            with loader.ssh_tunnel({}):
                pass
            spawn.assert_not_called()


class IndexerTests(unittest.TestCase):
    def test_missing_and_failed_indices_raise_instead_of_empty_success(self):
        for status in (404, 403, 500):
            with self.subTest(status=status):
                indexer = indexer_response(status)
                cur = Mock()
                with self.assertRaises(requests.HTTPError):
                    loader.snapshot_vulnerabilities(cur, indexer)
                cur.execute.assert_not_called()
                self.assertEqual(indexer.session.post.call_args.kwargs["params"],
                                 {"allow_no_indices": "false", "ignore_unavailable": "false"})

    def test_partial_search_preserves_snapshot(self):
        for metadata in ({"timed_out": True}, {"_shards": {"failed": 1}}, {"_shards": {"total": 0}}):
            with self.subTest(metadata=metadata):
                body = {"hits": {"hits": [], "total": {"value": 0, "relation": "eq"}}, **metadata}
                cur = Mock()
                with self.assertRaises(RuntimeError):
                    loader.snapshot_vulnerabilities(cur, indexer_response(body=body))
                cur.execute.assert_not_called()

    def test_truncated_or_unknown_total_preserves_snapshot(self):
        for total in (None, {"value": 1, "relation": "eq"}, {"value": 0, "relation": "gte"}):
            with self.subTest(total=total):
                cur = Mock()
                with self.assertRaises(RuntimeError):
                    loader.snapshot_vulnerabilities(cur, indexer_response(body={"hits": {"hits": [], "total": total}}))
                cur.execute.assert_not_called()

    def test_confirmed_empty_existing_index_can_replace_snapshot(self):
        cur = Mock()
        result = {"_shards": {"total": 1, "failed": 0}, "timed_out": False,
                  "hits": {"hits": [], "total": {"value": 0, "relation": "eq"}}}
        self.assertEqual(loader.snapshot_vulnerabilities(cur, indexer_response(body=result)), 0)
        self.assertIn("DELETE FROM sg.vulnerability_snapshots", cur.execute.call_args.args[0])


class ReconciliationTests(unittest.TestCase):
    def test_no_successful_full_scan_or_daily_deadline_requests_full_scan(self):
        for last in (None, NOW - timedelta(days=1), NOW - timedelta(days=3)):
            with self.subTest(last=last):
                cur = Mock()
                cur.execute.return_value.fetchone.return_value = (last,)
                self.assertIsNone(loader.get_watermark(cur, now=NOW))
                self.assertEqual(cur.execute.call_count, 1)
                self.assertIn("status = 'succeeded'", cur.execute.call_args.args[0])

    def test_normal_run_retains_overlap_and_caps_future_timestamps(self):
        for high_water in (NOW - timedelta(hours=1), NOW + timedelta(days=3)):
            with self.subTest(high_water=high_water):
                cur = Mock()
                cur.execute.return_value.fetchone.side_effect = [(NOW - timedelta(hours=1),), (high_water,)]
                self.assertEqual(loader.get_watermark(cur, now=NOW), min(high_water, NOW) - loader.OVERLAP)

    def test_explicit_reconciliation_does_not_use_watermark(self):
        cur = Mock()
        self.assertIsNone(loader.get_watermark(cur, reconcile=True, now=NOW))
        cur.execute.assert_not_called()

    def test_late_alert_is_in_daily_scan_but_not_incremental_window(self):
        late = {"_id": "late-test", "_source": {"timestamp": "2026-10-03T01:00:00.000+0000"}}
        indexer = Mock()

        def search(_index, body):
            return {"hits": {"hits": [late] if body["query"] == {"match_all": {}} else []}}

        indexer.search.side_effect = search
        self.assertEqual(list(loader.fetch_alert_pages(indexer, None)), [[late]])
        self.assertEqual(list(loader.fetch_alert_pages(indexer, NOW - loader.OVERLAP)), [])

    def test_replayed_document_is_not_inserted_again(self):
        cur = Mock()
        cur.execute.return_value = [("already-stored",)]
        self.assertEqual(loader.load_alert_page(cur, [{"_id": "already-stored"}]), 0)
        self.assertEqual(cur.execute.call_count, 1)

    def test_main_refreshes_summaries_for_old_reconciled_events(self):
        cur = Mock()
        cur.execute.return_value.fetchone.return_value = (123,)
        conn = Mock()
        conn.cursor.return_value = cur
        page = [{"_id": "late-test", "_source": {"timestamp": "2026-09-01T01:00:00.000+0000"}}]
        with patch.object(loader, "load_settings", return_value={}), \
             patch.object(loader.pyodbc, "connect", return_value=conn), \
             patch.object(loader, "ssh_tunnel"), patch.object(loader, "Indexer"), \
             patch.object(loader, "get_watermark", return_value=None), \
             patch.object(loader, "fetch_alert_pages", return_value=[page]), \
             patch.object(loader, "load_alert_page", return_value=1), \
             patch.object(loader, "snapshot_vulnerabilities", return_value=0), redirect_stdout(io.StringIO()):
            self.assertEqual(loader.main(["--reconcile"]), 0)
        summary = next(call for call in cur.execute.call_args_list if "refresh_daily_summary" in call.args[0])
        self.assertEqual(summary.args[1], datetime(2026, 8, 31).date())

    def test_snapshot_failure_records_failed_run(self):
        cur = Mock()
        cur.execute.return_value.fetchone.return_value = (123,)
        conn = Mock()
        conn.cursor.return_value = cur
        with patch.object(loader, "load_settings", return_value={}), \
             patch.object(loader.pyodbc, "connect", return_value=conn), \
             patch.object(loader, "ssh_tunnel"), patch.object(loader, "Indexer"), \
             patch.object(loader, "get_watermark", return_value=None), \
             patch.object(loader, "fetch_alert_pages", return_value=[]), \
             patch.object(loader, "snapshot_vulnerabilities", side_effect=RuntimeError("synthetic failure")), \
             redirect_stdout(io.StringIO()), patch.object(loader.sys, "stderr", io.StringIO()):
            self.assertEqual(loader.main([]), 1)
        conn.rollback.assert_called_once()
        update = next(call for call in cur.execute.call_args_list if "UPDATE sg.load_runs" in call.args[0])
        self.assertEqual(update.args[2], "failed")
        self.assertFalse(any("refresh_daily_summary" in call.args[0] for call in cur.execute.call_args_list))


class CaseWindowTests(unittest.TestCase):
    def args(self, **overrides):
        return types.SimpleNamespace(**{"rules": "100113", "since": NOW - timedelta(hours=1), "until": NOW,
                                        "title": "Synthetic incident", "severity": "High", "assign": None, **overrides})

    def test_new_case_uses_only_selected_incident_window(self):
        cur = Mock()
        cur.execute.return_value.fetchone.side_effect = [(NOW - timedelta(minutes=5),), (42,)]
        with redirect_stdout(io.StringIO()):
            cases.cmd_open(cur, self.args(rules="100113,100113"))
        first = cur.execute.call_args_list[0]
        self.assertIn("alert_ts_utc >= ? AND alert_ts_utc <= ?", first.args[0])
        self.assertEqual(first.args[1:], (100113, NOW - timedelta(hours=1), NOW))
        inserted = cur.execute.call_args_list[1]
        self.assertEqual(inserted.args[-1], NOW - timedelta(minutes=5))
        cur.executemany.assert_called_once()

    def test_empty_window_creates_no_case(self):
        cur = Mock()
        cur.execute.return_value.fetchone.return_value = (None,)
        with self.assertRaisesRegex(SystemExit, "selected incident window"):
            cases.cmd_open(cur, self.args())
        self.assertEqual(cur.execute.call_count, 1)
        cur.executemany.assert_not_called()

    def test_reversed_window_rejected_before_query(self):
        cur = Mock()
        with self.assertRaises(SystemExit):
            cases.cmd_open(cur, self.args(since=NOW + timedelta(hours=1)))
        cur.execute.assert_not_called()

    def test_timezone_required_and_offsets_normalized(self):
        self.assertEqual(cases.utc_timestamp("2026-10-04T08:00:00-04:00"), NOW)
        self.assertEqual(cases.utc_timestamp("2026-10-04T12:00:00Z"), NOW)
        for bad in ("2026-10-04T12:00:00", "not-a-date"):
            with self.subTest(bad=bad), self.assertRaises(cases.argparse.ArgumentTypeError):
                cases.utc_timestamp(bad)


if __name__ == "__main__":
    unittest.main()
