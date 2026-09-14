"""Offline watcher regressions: no SMTP, journald, or production state writes."""
import json
import queue
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import error_alerts as alerts


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in (("STATE_DIR", self.tmp.name),
                            ("STATE_PATH", str(Path(self.tmp.name) / "state.json"))):
            p = patch.object(alerts, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.mail = patch.object(alerts, "send_email", return_value=True).start()
        self.addCleanup(patch.stopall)
        alerts._recent_incidents.clear()
        alerts._recent_responses.clear()
        alerts._deferred.clear()
        alerts._rate_hits.clear()
        self.events = queue.Queue()
        self.state = alerts.State()

    def event(self, title="HTTP 500 on GET /dashboard", **overrides):
        return {"ts": time.time(), "source": "bearcats", "severity": "error",
                "title": title, "text": title, "signature": title, **overrides}

    def test_repeats_count_as_events_but_only_one_email(self):
        dispatcher = alerts.Dispatcher(self.state, self.events)
        dispatcher.handle(self.event())
        dispatcher.handle(self.event())
        self.assertEqual(self.mail.call_count, 1)
        self.assertEqual(len(self.state.history), 2)
        subject, body, _ = alerts.heartbeat_report(self.state)
        self.assertIn("2 error events", subject)
        self.assertIn("2x  HTTP 500", body)

    def test_weekly_totals_and_top_list_use_same_window(self):
        now = time.time()
        self.state.history_started_at = now - 20 * 86400
        self.state.history = [self.event(ts=now-8*86400), self.event(ts=now-10)]
        self.state.counters["error"] = 999
        self.state.seen["old"] = {"count": 999, "last": now}
        subject, body, _ = alerts.heartbeat_report(self.state, now)
        self.assertIn("1 error events", subject)
        self.assertNotIn("999", body)
        self.assertNotIn("Partial week", body)

    def test_legacy_state_reports_partial_coverage_without_inventing_history(self):
        Path(alerts.STATE_PATH).write_text(json.dumps({"counters": {"error": 158}}))
        state = alerts.State()
        subject, body, _ = alerts.heartbeat_report(state)
        self.assertIn("0 error events", subject)
        self.assertIn("Partial week", body)
        self.assertNotIn("158", body)

    def test_history_roundtrip_and_pruning(self):
        self.state.history_started_at = time.time() - 10 * 86400
        self.state.record(self.event(ts=time.time()-8*86400))
        self.state.record(self.event(severity="warning"))
        self.state.save()
        loaded = alerts.State()
        self.assertEqual(len(loaded.history), 1)
        self.assertEqual(loaded.history[0]["severity"], "warning")
        self.assertEqual(loaded.history_started_at, self.state.history_started_at)

    def test_history_cap_discloses_shorter_coverage(self):
        self.state.history_started_at = time.time() - 10 * 86400
        self.state.history = [self.event(ts=time.time()-i) for i in (30, 20, 10)]
        with patch.object(alerts, "MAX_HISTORY", 2):
            self.state.save()
        self.assertEqual(len(self.state.history), 2)
        self.assertEqual(self.state.history_started_at, self.state.history[0]["ts"])
        self.assertIn("Partial week", alerts.heartbeat_report(self.state)[1])

    def test_rate_limits_are_reported_separately_and_only_sustained_hits_notify(self):
        line = ('2026/09/14 12:00:00 [error] 123#123: *4 limiting requests, '
                'excess: 3.000 by zone "cap_general", client: 192.0.2.1, server: caprecruiting.com')
        with patch.object(alerts, "tail_file", return_value=iter([line] * 5)):
            alerts.file_watcher(self.events, "nginx", "unused")
        dispatcher = alerts.Dispatcher(self.state, self.events)
        for i in range(5):
            event = self.events.get_nowait()
            self.assertEqual(event["notify"], i == 4)
            dispatcher.handle(event)
        self.assertEqual(self.mail.call_count, 1)
        subject, body, _ = alerts.heartbeat_report(self.state)
        self.assertIn("0 error events, 5 rate-limit blocks", subject)
        self.assertIn("Other warnings: 0", body)

    def test_response_and_access_log_count_once_without_hiding_other_clients(self):
        richer = ('2026-09-14 12:00:00,000 ERROR bearcats: [APP-ERROR] HTTP 413 '
                  'returned by POST /profile/upload-committed-logo (user=anon ip=192.0.2.1)')
        alerts.mark_response_incident(richer)
        access = 'INFO: 192.0.2.1:0 - "POST /profile/upload-committed-logo HTTP/1.1" 413 Request Entity Too Large'
        self.assertTrue(alerts.recent_response(access))
        self.assertFalse(alerts.recent_response(access.replace("192.0.2.1", "192.0.2.2")))
        self.assertFalse(alerts.recent_response(access.replace('POST ', 'PUT ')))
        alerts._deferred.append((0, "bearcats", "upload", access, "error", "/profile/upload-committed-logo"))
        alerts.drain_deferred(self.events)
        self.assertTrue(self.events.empty())

    def test_heartbeat_does_not_write_state_even_when_email_fails(self):
        self.state.save()
        before = Path(alerts.STATE_PATH).read_bytes()
        self.mail.return_value = False
        self.assertEqual(alerts.send_heartbeat(), 1)
        self.assertEqual(Path(alerts.STATE_PATH).read_bytes(), before)

    def test_unplanned_connection_failure_still_alerts(self):
        line = ('2026/09/14 12:00:00 [error] 123#123: *4 connect() failed '
                '(111: Connection refused) while connecting to upstream')
        with patch.object(alerts, "tail_file", return_value=iter([line])), \
             patch.object(alerts, "app_restarting", return_value=False):
            alerts.file_watcher(self.events, "nginx", "unused")
        self.assertEqual(self.events.get_nowait()["severity"], "error")


if __name__ == "__main__":
    unittest.main()
