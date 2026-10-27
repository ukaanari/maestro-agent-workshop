"""Load stock rows from CSV text with the header sku,name,category,quantity."""
import csv
import io

from .models import Item

FIELDS = ["sku", "name", "category", "quantity"]


def load_rows(text):
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames != FIELDS:
        raise ValueError("expected header: " + ",".join(FIELDS))
    return [Item(row["sku"], row["name"], row["category"], int(row["quantity"])) for row in reader]
