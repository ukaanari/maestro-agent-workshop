Harden the CSV import in src/stockroom/importer.py.

1. A row with a negative quantity must raise stockroom.errors.ImportRowError, a ValueError
   subclass whose message names the 1-based CSV line, for example "line 3". This applies
   to every row, including rows that repeat a SKU.
2. Rows that repeat a SKU are merged into one Item by adding their quantities; the first
   row's name and category are kept.
3. Keep the public API: load_rows(text) returns a list of Item in first-seen order.

Create src/stockroom/errors.py for the exception. Do not change the tests.
