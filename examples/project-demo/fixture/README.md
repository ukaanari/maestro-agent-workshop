# stockroom

A tiny inventory library: load stock rows from CSV text and total them per category.
This is a synthetic MAESTRO example project, not a real product.

Layout: `src/stockroom/` (the package) and `tests/` (a unittest package that imports
`stockroom` and its own helpers), so verification needs `--pythonpath src --top-level-dir .`.
