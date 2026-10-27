"""Load stock rows from CSV text with the header sku,name,category,quantity."""
import csv
import dataclasses
import io

from .errors import ImportRowError
from .models import Item

FIELDS = ["sku", "name", "category", "quantity"]


def load_rows(text):
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames != FIELDS:
        raise ValueError("expected header: " + ",".join(FIELDS))
    items = {}
    for row in reader:
        quantity = int(row["quantity"])
        first = items.get(row["sku"])
        if first is None:
            if quantity < 0:
                raise ImportRowError("line %d: negative quantity for %s" % (reader.line_num, row["sku"]))
            items[row["sku"]] = Item(row["sku"], row["name"], row["category"], quantity)
        else:
            items[row["sku"]] = dataclasses.replace(first, quantity=first.quantity + quantity)
    return list(items.values())
