from vibap.shareable_redaction import (
    file_uri_placeholder,
    local_path_leak_hits,
    redact_local_path_text,
    replace_path_roots,
)


def test_replace_path_roots_uses_longest_match_first_for_overlapping_roots() -> None:
    text = "/tmp/foobar/output.json and /tmp/foo/input.json"

    redacted = replace_path_roots(
        text,
        (
            ("/tmp/foo", "<FOO>"),
            ("/tmp/foobar", "<FOOBAR>"),
        ),
    )

    assert redacted == "<FOOBAR>/output.json and <FOO>/input.json"


def test_redacted_placeholder_relative_paths_are_not_reported_as_absolute_leaks() -> None:
    redacted = redact_local_path_text(
        "receipt at /private/tmp/ardur-run/project/ARDUR.md",
        root_pairs=(("/private/tmp/ardur-run/project", "<RWT_PROJECT>"),),
    )

    assert redacted == "receipt at <RWT_PROJECT>/ARDUR.md"
    assert local_path_leak_hits(redacted, extra_markers=("/private/tmp/ardur-run",)) == []


def test_file_uri_variants_are_redacted_and_detected() -> None:
    text = "open file://localhost/Users/rahul/project/secret.txt or file:///tmp/ardur/out.json"

    assert "file://localhost/Users/rahul/project/secret.txt" in local_path_leak_hits(text)
    assert "file:///tmp/ardur/out.json" in local_path_leak_hits(text)

    redacted = redact_local_path_text(text)

    assert redacted == "open <FILE_URI:/Users> or <FILE_URI:/tmp>"
    assert local_path_leak_hits(redacted) == []


def test_file_uri_placeholder_falls_back_to_local_for_unrecognized_roots() -> None:
    assert file_uri_placeholder("file:///opt/ardur/secret.txt") == "<FILE_URI:local>"
