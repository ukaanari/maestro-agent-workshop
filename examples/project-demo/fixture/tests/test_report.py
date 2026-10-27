import unittest

from stockroom.models import Item
from stockroom.report import totals_by_category


class ReportTests(unittest.TestCase):
    def test_totals_per_category(self):
        items = [Item("A1", "Bolt", "hardware", 5), Item("C3", "Nut", "hardware", 7),
                 Item("B2", "Glue", "supplies", 2)]
        self.assertEqual(totals_by_category(items), {"hardware": 12, "supplies": 2})

    def test_no_items(self):
        self.assertEqual(totals_by_category([]), {})
