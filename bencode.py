"""Minimal bencoding (BEP 3) encoder/decoder."""


def bencode(obj) -> bytes:
    if isinstance(obj, bool):
        raise TypeError("bool is not bencodable")
    if isinstance(obj, int):
        return b"i%de" % obj
    if isinstance(obj, str):
        obj = obj.encode("utf-8")
    if isinstance(obj, (bytes, bytearray)):
        return b"%d:%s" % (len(obj), bytes(obj))
    if isinstance(obj, (list, tuple)):
        return b"l" + b"".join(bencode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        items = []
        for key in sorted(k.encode("utf-8") if isinstance(k, str) else bytes(k) for k in obj):
            skey = key.decode("utf-8", "surrogateescape")
            val = obj.get(key, obj.get(skey))
            items.append(bencode(key) + bencode(val))
        return b"d" + b"".join(items) + b"e"
    raise TypeError(f"cannot bencode {type(obj)!r}")


def bdecode(data: bytes):
    obj, rest = _decode(memoryview(data), 0)
    if rest != len(data):
        raise ValueError("trailing data after bencoded value")
    return obj


def _decode(mv, i):
    c = mv[i : i + 1].tobytes()
    if c == b"i":
        end = _find(mv, b"e", i)
        return int(mv[i + 1 : end].tobytes()), end + 1
    if c == b"l":
        i += 1
        out = []
        while mv[i : i + 1].tobytes() != b"e":
            item, i = _decode(mv, i)
            out.append(item)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while mv[i : i + 1].tobytes() != b"e":
            key, i = _decode(mv, i)
            val, i = _decode(mv, i)
            out[key] = val
        return out, i + 1
    if c.isdigit():
        colon = _find(mv, b":", i)
        length = int(mv[i:colon].tobytes())
        start = colon + 1
        if start + length > len(mv):
            raise ValueError("string length past end of data")
        return mv[start : start + length].tobytes(), start + length
    raise ValueError(f"invalid bencode at offset {i}")


def _find(mv, char, start):
    i = start
    while i < len(mv):
        if mv[i : i + 1].tobytes() == char:
            return i
        i += 1
    raise ValueError("unterminated bencode value")
