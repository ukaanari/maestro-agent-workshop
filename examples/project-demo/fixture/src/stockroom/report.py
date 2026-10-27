from collections import Counter


def totals_by_category(items):
    totals = Counter()
    for item in items:
        totals[item.category] += item.quantity
    return dict(sorted(totals.items()))
