import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from calc import add


class AdditionTests(unittest.TestCase):
    def test_addition(self):
        for a, b in ((2, 3), (-2, 5), (0, 0), (-7, -3)):
            with self.subTest(a=a, b=b):
                self.assertEqual(add(a, b), a + b)
