for x in range(1000):
    bytes = x.to_bytes(8, 'big')
    print(f"{x} - {len(bytes)}")
    print(f"Comin bak: {int.from_bytes(bytes, 'big')}")
