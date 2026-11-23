"""Edit config.yaml text in place, keeping comments and layout.

PyYAML can't round-trip comments, so instead of loading and dumping the whole file we
use the positions of the parsed nodes and change only the text that has to change:

    set_in(text, ["channels", 1, "devices", 0, "ip"], "192.168.1.11")
    delete_in(text, [..., "polling", "rssi_warning_dbm"])
    append_to(text, ["channels", 1, "devices"], {"name": "Master2", ...})
    remove_from(text, ["channels", 1, "devices"], 0)

Everything outside the edited value stays byte-for-byte the same. Values that don't exist
yet are inserted with the indentation of their siblings.
"""
from __future__ import annotations

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class YamlEditError(ValueError):
    pass


def _scalar(value) -> str:
    out = yaml.safe_dump(value, default_flow_style=True, width=100000, allow_unicode=True)
    out = out.rstrip("\n")
    if out.endswith("\n..."):
        out = out[:-4]
    return out.strip()


def _block(value, indent: int) -> str:
    """Block-style YAML for a mapping/sequence, every line indented by `indent` spaces."""
    dumped = yaml.safe_dump(value, default_flow_style=False, sort_keys=False, width=100000, allow_unicode=True)
    return "".join(" " * indent + line + "\n" for line in dumped.rstrip("\n").split("\n"))


def _flow(value) -> str:
    return yaml.safe_dump(value, default_flow_style=True, sort_keys=False, width=100000,
                          allow_unicode=True).strip()


def _find(root: Node | None, path: list) -> tuple[Node | None, Node | None, Node | None]:
    """(node, key node, parent node) at path; node is None if the last step is missing."""
    node, key_node, parent = root, None, None
    for step in path:
        if node is None:
            return None, None, None
        parent = node
        if isinstance(node, MappingNode):
            hit = next(((k, v) for k, v in node.value if isinstance(k, ScalarNode) and k.value == str(step)), None)
            if hit is None:
                return None, None, parent
            key_node, node = hit
        elif isinstance(node, SequenceNode) and isinstance(step, int):
            if not 0 <= step < len(node.value):
                return None, None, parent
            key_node, node = None, node.value[step]
        else:
            return None, None, parent
    return node, key_node, parent


def _content_end(node: Node) -> int:
    """Index just after the last real content of a node (ignores trailing comments/blank lines)."""
    if isinstance(node, MappingNode) and node.value and not node.flow_style:
        return _content_end(node.value[-1][1])
    if isinstance(node, SequenceNode) and node.value and not node.flow_style:
        return _content_end(node.value[-1])
    return node.end_mark.index


def _line_start(text: str, index: int) -> int:
    return text.rfind("\n", 0, index) + 1


def _eol(text: str, index: int) -> int:
    """Index of the newline ending the line that contains `index` (after any trailing comment)."""
    nl = text.find("\n", index)
    return len(text) if nl == -1 else nl


def _line_end(text: str, index: int) -> int:
    """Index after the newline that ends the line containing `index` (or len(text))."""
    nl = text.find("\n", index)
    return len(text) if nl == -1 else nl + 1


def _compose(text: str) -> Node | None:
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise YamlEditError(f"The configuration isn't valid YAML: {exc}") from None


def _value_at(text: str, path: list):
    data = yaml.safe_load(text)
    for step in path:
        data = data[step]
    return data


def _key_indent(node: MappingNode) -> int:
    return node.value[0][0].start_mark.column


def set_in(text: str, path: list, value) -> str:
    """Set the value at path (creating missing mappings). Dicts merge into existing block mappings."""
    if not path:
        raise YamlEditError("empty path")
    root = _compose(text)
    node, key_node, parent = _find(root, path)

    if node is not None:
        if isinstance(value, dict) and isinstance(node, MappingNode) and not node.flow_style and node.value:
            for k, v in value.items():
                text = set_in(text, path + [k], v)
            return text
        if not isinstance(value, (dict, list)):
            if isinstance(node, ScalarNode) or node.flow_style:
                return text[:node.start_mark.index] + _scalar(value) + text[node.end_mark.index:]
        if isinstance(node, ScalarNode) or node.flow_style:
            if isinstance(value, (dict, list)) and value and key_node is not None:
                indent = key_node.start_mark.column + 2
                # "key: {}" -> "key:\n  block..."
                start = key_node.end_mark.index
                colon = text.index(":", start)
                return text[:colon + 1] + "\n" + _block(value, indent).rstrip("\n") + text[node.end_mark.index:]
            return text[:node.start_mark.index] + _flow(value) + text[node.end_mark.index:]
        # block mapping/sequence replaced by something else: rewrite the whole value
        if key_node is None:
            raise YamlEditError(f"can't replace the list item at {path}")
        indent = key_node.start_mark.column + 2
        colon = text.index(":", key_node.end_mark.index)
        end = _content_end(node)
        if isinstance(value, (dict, list)) and value:
            return text[:colon + 1] + "\n" + _block(value, indent).rstrip("\n") + text[end:]
        return text[:colon + 1] + " " + (_flow(value) if isinstance(value, (dict, list)) else _scalar(value)) \
            + text[end:]

    # missing: make sure the parent exists, then insert
    parent_node, parent_key, _ = _find(root, path[:-1]) if len(path) > 1 else (root, None, None)
    if parent_node is None:
        return set_in(text, path[:-1], {path[-1]: value})
    key = path[-1]
    if isinstance(parent_node, ScalarNode) and parent_node.value in ("", "null", "~"):
        if parent_key is None:
            raise YamlEditError(f"can't add {key} at the top of an empty file")
        return set_in(text, path[:-1], {key: value})
    if not isinstance(parent_node, MappingNode):
        raise YamlEditError(f"{'.'.join(map(str, path[:-1]))} is not a mapping")
    if parent_node.flow_style or not parent_node.value:
        merged = dict(_value_at(text, path[:-1]) or {})
        merged[key] = value
        return text[:parent_node.start_mark.index] + _flow(merged) + text[parent_node.end_mark.index:]
    indent = _key_indent(parent_node)
    at = _eol(text, _content_end(parent_node) - 1)      # after the last line's trailing comment
    if isinstance(value, (dict, list)) and value:
        piece = f"\n{' ' * indent}{key}:\n" + _block(value, indent + 2).rstrip("\n")
    else:
        piece = f"\n{' ' * indent}{key}: " + (_flow(value) if isinstance(value, (dict, list)) else _scalar(value))
    return text[:at] + piece + text[at:]


def delete_in(text: str, path: list) -> str:
    """Remove a key (no-op if it isn't there)."""
    root = _compose(text)
    node, key_node, parent = _find(root, path)
    if node is None or key_node is None or not isinstance(parent, MappingNode):
        return text
    if parent.flow_style or len(parent.value) == 1:
        remaining = dict(_value_at(text, path[:-1]))
        remaining.pop(path[-1], None)
        if parent.flow_style:
            return text[:parent.start_mark.index] + _flow(remaining) + text[parent.end_mark.index:]
        return set_in(text, path[:-1], remaining)
    start = _line_start(text, key_node.start_mark.index)
    end = _line_end(text, max(_content_end(node) - 1, key_node.start_mark.index))
    return text[:start] + text[end:]


def append_to(text: str, path: list, item) -> str:
    """Append an item to the list at path (created if missing)."""
    root = _compose(text)
    node, key_node, _ = _find(root, path)
    if node is None or (isinstance(node, ScalarNode) and node.value in ("", "null", "~")):
        return set_in(text, path, [item])
    if not isinstance(node, SequenceNode):
        raise YamlEditError(f"{'.'.join(map(str, path))} is not a list")
    if node.flow_style or not node.value:
        items = list(_value_at(text, path) or []) + [item]
        return set_in(text, path, items) if not node.value else \
            text[:node.start_mark.index] + _flow(items) + text[node.end_mark.index:]
    dash_col = node.start_mark.column
    at = _eol(text, _content_end(node) - 1)
    return text[:at] + "\n" + _block([item], dash_col).rstrip("\n") + text[at:]


def remove_from(text: str, path: list, index: int) -> str:
    """Remove item `index` from the list at path."""
    root = _compose(text)
    node, key_node, _ = _find(root, path)
    if not isinstance(node, SequenceNode) or not 0 <= index < len(node.value):
        raise YamlEditError(f"no item {index} at {'.'.join(map(str, path))}")
    if node.flow_style or len(node.value) == 1:
        items = list(_value_at(text, path))
        del items[index]
        return set_in(text, path, items)
    item = node.value[index]
    start = _line_start(text, item.start_mark.index)
    if index + 1 < len(node.value):
        end = _line_start(text, node.value[index + 1].start_mark.index)
    else:
        start = _line_end(text, _content_end(node.value[index - 1]) - 1)
        end = _line_end(text, _content_end(item) - 1)
        # keep the newline that ended the previous item's last line
        return text[:start] + text[end:] if end < len(text) else text[:start].rstrip("\n") + "\n"
    return text[:start] + text[end:]
