# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Result envelope, codes and the size cap (contract H.1, H.2, H.2.1)."""

from __future__ import annotations

import json

import pytest

from sniper_mcp import results


def test_success_shape_and_order():
    result = results.success("tool_x", {"warnings": ["ignored"], "b": 1, "tool": "no",
                                        "a": "x"}, [results.warning("loot_dir_missing", "m")])
    payload = result.structuredContent
    assert list(payload) == ["schema_version", "tool", "b", "a", "warnings"]
    assert payload["tool"] == "tool_x"
    assert payload["warnings"] == [{"code": "loot_dir_missing", "message": "m"}]
    assert result.isError is False
    assert result.content[0].text == results.encode(payload)


def test_failure_shape():
    result = results.failure("sniper_scan", "out_of_scope", "Target is outside.", "Ask.",
                             details={"target": "app.example"})
    assert result.isError is True
    assert result.structuredContent == {
        "schema_version": "1", "tool": "sniper_scan",
        "error": {"code": "out_of_scope", "message": "Target is outside.", "hint": "Ask.",
                  "retry": "never", "details": {"target": "app.example"}}}


def test_unknown_codes_are_programming_errors():
    with pytest.raises(ValueError):
        results.ToolError("not_a_code", "m", "h")
    with pytest.raises(ValueError):
        results.warning("not_a_warning", "m")
    with pytest.raises(ValueError):
        results.ToolError("internal_error", "m", "h", retry="sometimes")


def test_error_and_warning_code_tables_are_pinned():
    # Pinned against the H.2 and H.2.1 tables; codes are stable identifiers (S.5).
    assert len(results.ERROR_CODES) == 58
    assert sum(1 for r in results.ERROR_CODES.values() if r == "never") == 18
    assert results.ERROR_CODES["dns_timeout"] == "later"
    assert results.ERROR_CODES["mode_not_allowed"] == "never"
    assert results.ERROR_CODES["sudo_untrusted"] == "after_change"
    # 27 since the 2026-10-12 amendment added install_dir_marker_untrusted (C.2 step 3,
    # S2 residual B4).
    assert len(results.WARNING_CODES) == 27
    assert "install_dir_marker_untrusted" in results.WARNING_CODES


def test_untrusted_notice_and_page():
    content = results.untrusted(lines=["x"])
    assert list(content) == ["notice", "lines"]
    assert content["notice"].startswith("UNTRUSTED DATA:")
    assert results.page(0, 2, 2, 5) == {"offset": 0, "limit": 2, "returned": 2, "total": 5,
                                         "next_offset": 2}
    assert results.page(4, 2, 1, 5)["next_offset"] is None


def test_oversized_payload_is_shortened_with_a_warning():
    big = "A" * 200_000
    result = results.success("grep_loot", {"untrusted_content": results.untrusted(text=big)})
    payload = result.structuredContent
    assert results.encoded_size(payload) <= results.MAX_STRUCTURED_BYTES
    assert payload["untrusted_content"]["text"].endswith("[truncated]")
    assert payload["untrusted_content"]["notice"].startswith("UNTRUSTED DATA")
    assert payload["warnings"][-1]["code"] == "response_truncated"


def test_shrinking_never_touches_sources_and_merges_repeated_warnings():
    sources = [{"path": "nmap/nmap-" + "h" * 100 + ".txt"}] * 3
    body = {"sources": sources, "untrusted_content": results.untrusted(text="B" * 200_000)}
    warnings = [results.warning("response_truncated", "Fields were cut."),
                results.warning("unreadable_entries", "One."),
                results.warning("unreadable_entries", "Two.")]
    payload = results.success("get_ports", body, warnings).structuredContent
    assert payload["sources"] == sources
    assert results.encoded_size(payload) <= results.MAX_STRUCTURED_BYTES
    assert [w["code"] for w in payload["warnings"]] == ["response_truncated",
                                                        "unreadable_entries"]
    assert payload["warnings"][1]["message"] == "One. Two."
    assert payload["warnings"][0]["message"].startswith("Fields were cut. Some strings")


def test_multibyte_payload_respects_the_byte_cap():
    result = results.success("x", {"items": ["é" * 30_000, "中" * 30_000]})
    assert len(result.content[0].text.encode("utf-8")) <= results.MAX_STRUCTURED_BYTES


def test_an_undecodable_path_byte_never_turns_a_result_into_internal_error():
    """A path that is not valid UTF-8 reaches Python as surrogate escapes, which a UTF-8
    result cannot carry; they become visible <U+XXXX> text (as in J.6 step 6)."""
    path = "/opt/cli\udcff"
    ok = results.success("sniper_status", {"paths": {"sniper_bin": path, "n": 1},
                                            "list": [path, ("a", path)]},
                         [results.warning("install_world_writable", path)])
    assert ok.structuredContent["paths"] == {"sniper_bin": "/opt/cli<U+DCFF>", "n": 1}
    assert ok.structuredContent["list"] == ["/opt/cli<U+DCFF>", ["a", "/opt/cli<U+DCFF>"]]
    assert ok.structuredContent["warnings"][0]["message"] == "/opt/cli<U+DCFF>"
    ok.content[0].text.encode("utf-8")
    for refused in (results.failure("sniper_scan", "cli_untrusted", "m", f"chown {path}",
                                    details={"p": path}),
                    results.plugin_failure("t", "acme_failed", "m", path, retry="never")):
        error = refused.structuredContent["error"]
        assert "<U+DCFF>" in error["hint"] and "\udcff" not in refused.content[0].text
    plain = {"paths": {"sniper_bin": "/opt/cli"}}
    assert results.visible_surrogates(plain) == plain


def test_count_within_cap():
    records = ["r" * 1000] * 200

    def build(n):
        return {"schema_version": "1", "tool": "t", "items": records[:n]}

    n = results.count_within_cap(build, len(records))
    assert results.encoded_size(build(n)) <= results.MAX_STRUCTURED_BYTES
    assert results.encoded_size(build(n + 1)) > results.MAX_STRUCTURED_BYTES
    assert results.count_within_cap(build, 3) == 3


async def test_guarded_maps_exceptions():
    @results.guarded("t")
    async def refuses():
        raise results.ToolError("scan_disabled", "off", "turn on")

    @results.guarded("t")
    async def crashes():
        raise RuntimeError("secret detail that must not reach the model")

    refused = await refuses()
    assert refused.isError and refused.structuredContent["error"]["code"] == "scan_disabled"
    crashed = await crashes()
    assert crashed.structuredContent["error"]["code"] == "internal_error"
    assert "secret detail" not in json.dumps(crashed.structuredContent)
