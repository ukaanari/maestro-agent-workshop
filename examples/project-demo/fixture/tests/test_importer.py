import unittest

from stockroom.importer import load_rows
from stockroom.models import Item

from .helpers import csv_text


class LoadRowsTests(unittest.TestCase):
    def test_parses_rows_in_order(self):
        items = load_rows(csv_text("A1,Bolt,hardware,5", "B2,Glue,supplies,2"))
        self.assertEqual(items, [Item("A1", "Bolt", "hardware", 5), Item("B2", "Glue", "supplies", 2)])

    def test_rejects_a_wrong_header(self):
        with self.assertRaises(ValueError):
            load_rows("id,name\nA1,Bolt\n")

    def test_rejects_a_non_integer_quantity(self):
        with self.assertRaises(ValueError):
            load_rows(csv_text("A1,Bolt,hardware,five"))

    def test_rejects_a_negative_quantity_naming_the_line(self):
        with self.assertRaises(ValueError) as caught:
            load_rows(csv_text("A1,Bolt,hardware,5", "B2,Glue,supplies,-1"))
        self.assertEqual(type(caught.exception).__name__, "ImportRowError")
        self.assertIn("line 3", str(caught.exception))

    def test_merges_rows_that_repeat_a_sku(self):
        items = load_rows(csv_text("A1,Bolt,hardware,5", "B2,Glue,supplies,2", "A1,Bolt (old),misc,4"))
        self.assertEqual(items, [Item("A1", "Bolt", "hardware", 9), Item("B2", "Glue", "supplies", 2)])

    def test_rejects_a_negative_quantity_in_a_repeated_sku(self):
        with self.assertRaises(ValueError) as caught:
            load_rows(csv_text("A1,Bolt,hardware,5", "A1,Bolt,hardware,-9"))
        self.assertIn("line 3", str(caught.exception))
