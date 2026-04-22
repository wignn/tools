from __future__ import annotations

import base64
import html
import urllib.parse


def to_base64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def from_base64(data: str) -> str:
    return base64.b64decode(data).decode(errors="replace")


def to_url(data: str) -> str:
    return urllib.parse.quote(data, safe="")


def from_url(data: str) -> str:
    return urllib.parse.unquote(data)


def to_double_url(data: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")


def to_hex(data: str) -> str:
    return data.encode().hex()


def from_hex(data: str) -> str:
    return bytes.fromhex(data).decode(errors="replace")


def to_html_entities(data: str) -> str:
    return "".join(f"&#{ord(c)};" for c in data)


def from_html(data: str) -> str:
    return html.unescape(data)


def to_unicode_escape(data: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in data)


def to_js_char_codes(data: str) -> str:
    codes = ",".join(str(ord(c)) for c in data)
    return f"String.fromCharCode({codes})"


def chain_encode(data: str, encodings: list[str]) -> str:
    result = data
    dispatch = {
        "base64": to_base64,
        "url": to_url,
        "double-url": to_double_url,
        "hex": to_hex,
        "html": to_html_entities,
        "unicode": to_unicode_escape,
    }
    for enc in encodings:
        fn = dispatch.get(enc)
        if fn:
            result = fn(result)
    return result


ENCODERS = {
    "base64": to_base64,
    "url": to_url,
    "double-url": to_double_url,
    "hex": to_hex,
    "html": to_html_entities,
    "unicode": to_unicode_escape,
    "js-charcode": to_js_char_codes,
}

DECODERS = {
    "base64": from_base64,
    "url": from_url,
    "hex": from_hex,
    "html": from_html,
}
