def csv_text(*rows):
    return "\n".join(["sku,name,category,quantity", *rows]) + "\n"
