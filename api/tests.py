from datetime import datetime
from zoneinfo import ZoneInfo

from django.test import SimpleTestCase

from .utils.incident_report import format_report_datetime_chicago


class ReportDatetimeChicagoTests(SimpleTestCase):
    def test_formats_utc_in_chicago(self):
        dt = datetime(2026, 1, 15, 18, 0, tzinfo=ZoneInfo("UTC"))
        s = format_report_datetime_chicago(dt)
        self.assertIn("January", s)
        self.assertIn("2026", s)
        self.assertIn("15", s)
        self.assertIn("12:00", s)
