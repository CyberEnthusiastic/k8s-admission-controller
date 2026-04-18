"""
yaml_mini - Minimal YAML subset parser for Kubernetes manifests.
Only used when PyYAML is not installed. Supports:
  - key: value (strings, ints, floats, bools, null)
  - nested mappings (indentation-based)
  - sequences (- item)
  - multi-document streams (--- separator)
  - quoted strings (single/double)
  - comments (# to EOL)

This is intentionally not a full YAML 1.2 implementation. It's good
enough to parse the K8s manifest subset used in samples/, but for
production use you should `pip install pyyaml`.
"""
import re


def safe_load_all(text):
    # Split multi-doc
    docs = re.split(r"^---\s*$", text, flags=re.MULTILINE)
    for raw in docs:
        raw = raw.strip("\n")
        if not raw.strip():
            continue
        lines = _preclean(raw.splitlines())
        if not lines:
            continue
        value, _ = _parse_block(lines, 0, 0)
        yield value


def _preclean(lines):
    out = []
    for ln in lines:
        stripped = ln.rstrip()
        # Remove comments that aren't inside quotes (approximate)
        m = re.match(r'^(.*?)(?<!["\'])\s+#.*$', stripped)
        if m and not _line_has_value_with_hash(stripped):
            stripped = m.group(1).rstrip()
        if stripped.strip().startswith("#"):
            continue
        if stripped.strip():
            out.append(stripped)
    return out


def _line_has_value_with_hash(line):
    # Rough heuristic: if there's a quoted string, leave the line alone
    return '"' in line or "'" in line


def _indent_of(line):
    return len(line) - len(line.lstrip(" "))


def _parse_scalar(s):
    s = s.strip()
    if s == "" or s in ("~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if re.match(r"^-?\d+$", s):
        return int(s)
    if re.match(r"^-?\d+\.\d+$", s):
        return float(s)
    return s


def _parse_block(lines, start, indent):
    """Return (parsed_value, next_index) starting at lines[start], at `indent` spaces."""
    if start >= len(lines):
        return None, start
    first = lines[start]
    first_indent = _indent_of(first)
    if first_indent < indent:
        return None, start
    content = first.strip()
    if content.startswith("- "):
        return _parse_sequence(lines, start, first_indent)
    return _parse_mapping(lines, start, first_indent)


def _parse_mapping(lines, start, indent):
    result = {}
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _indent_of(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            i += 1
            continue
        content = line.strip()
        if content.startswith("- "):
            break
        if ":" not in content:
            i += 1
            continue
        key, _, rest = content.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            result[key] = _parse_inline(rest)
            i += 1
        else:
            # Block value on next line(s)
            j = i + 1
            while j < len(lines) and _indent_of(lines[j]) <= indent and lines[j].strip() == "":
                j += 1
            if j >= len(lines) or _indent_of(lines[j]) <= indent:
                result[key] = None
                i = j
            else:
                child_indent = _indent_of(lines[j])
                value, next_i = _parse_block(lines, j, child_indent)
                result[key] = value
                i = next_i
    return result, i


def _parse_sequence(lines, start, indent):
    result = []
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _indent_of(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            i += 1
            continue
        content = line.strip()
        if not content.startswith("- "):
            break
        item_body = content[2:].strip()
        if ":" in item_body and not item_body.startswith(("\"", "'")):
            # Inline mapping start; construct synthetic sub-block
            sub_indent = indent + 2
            sub_lines = [" " * sub_indent + item_body]
            j = i + 1
            while j < len(lines) and _indent_of(lines[j]) > indent:
                sub_lines.append(lines[j])
                j += 1
            value, _ = _parse_mapping(sub_lines, 0, sub_indent)
            result.append(value)
            i = j
        elif item_body == "":
            # Nested block for this list item
            j = i + 1
            while j < len(lines) and _indent_of(lines[j]) > indent:
                j += 1
            if j > i + 1:
                inner, _ = _parse_block(lines[i+1:j], 0, _indent_of(lines[i+1]))
                result.append(inner)
            else:
                result.append(None)
            i = j
        else:
            result.append(_parse_inline(item_body))
            i += 1
    return result, i


def _parse_inline(s):
    s = s.strip()
    # Inline flow mappings {a: 1, b: 2}
    if s.startswith("{") and s.endswith("}"):
        out = {}
        body = s[1:-1].strip()
        if body:
            for part in _split_flow(body):
                k, _, v = part.partition(":")
                out[k.strip()] = _parse_inline(v.strip())
        return out
    if s.startswith("[") and s.endswith("]"):
        body = s[1:-1].strip()
        if not body:
            return []
        return [_parse_inline(x.strip()) for x in _split_flow(body)]
    return _parse_scalar(s)


def _split_flow(s):
    out, cur, depth = [], "", 0
    q = None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in ("'", '"'):
            q = ch; cur += ch; continue
        if ch in "[{":
            depth += 1; cur += ch; continue
        if ch in "]}":
            depth -= 1; cur += ch; continue
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""; continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out
