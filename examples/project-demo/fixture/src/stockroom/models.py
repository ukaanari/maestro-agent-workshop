from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    sku: str
    name: str
    category: str
    quantity: int
