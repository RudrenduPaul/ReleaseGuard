from releaseguard.readers import DEFAULT_READERS, get_reader_for
from releaseguard.readers.csv_reader import CsvReader
from releaseguard.readers.json_reader import JsonReader
from releaseguard.readers.text_reader import TextReader


def test_get_reader_for_dispatches_by_extension():
    assert isinstance(get_reader_for("data.csv"), CsvReader)
    assert isinstance(get_reader_for("data.json"), JsonReader)
    assert isinstance(get_reader_for("data.jsonl"), JsonReader)
    assert isinstance(get_reader_for("notes.txt"), TextReader)
    assert get_reader_for("model.bin") is None


def test_default_readers_registry_has_one_entry_per_format():
    format_names = {r.format_name for r in DEFAULT_READERS}
    assert format_names == {"csv", "json", "text"}


def test_text_reader_yields_one_fragment_per_nonblank_line(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("line one\n\nline two\n")
    fragments = list(TextReader().read_fragments(str(path)))
    assert [f.text for f in fragments] == ["line one", "line two"]
    assert [f.line_number for f in fragments] == [1, 3]


def test_csv_reader_yields_one_fragment_per_nonempty_cell(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("name,email\nJohn Smith,john@example.com\nJane,\n")
    fragments = list(CsvReader().read_fragments(str(path)))
    assert fragments[0].text == "John Smith"
    assert fragments[0].field_name == "name"
    assert fragments[0].line_number == 2
    assert fragments[1].text == "john@example.com"
    assert fragments[1].field_name == "email"
    # The empty "email" cell on Jane's row is skipped.
    assert [f.text for f in fragments] == ["John Smith", "john@example.com", "Jane"]


def test_json_reader_walks_nested_structure(tmp_path):
    path = tmp_path / "data.json"
    path.write_text('{"user": {"name": "John Smith", "tags": ["a", "b"]}}')
    fragments = list(JsonReader().read_fragments(str(path)))
    by_field = {f.field_name: f.text for f in fragments}
    assert by_field["user.name"] == "John Smith"
    assert by_field["user.tags[0]"] == "a"
    assert by_field["user.tags[1]"] == "b"


def test_jsonl_reader_tracks_line_number_per_record(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text('{"text": "first"}\n{"text": "second"}\n')
    fragments = list(JsonReader().read_fragments(str(path)))
    assert [(f.line_number, f.text) for f in fragments] == [(1, "first"), (2, "second")]


def test_json_reader_skips_malformed_lines_in_jsonl(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text('{"text": "ok"}\nnot json\n{"text": "also ok"}\n')
    fragments = list(JsonReader().read_fragments(str(path)))
    assert [f.text for f in fragments] == ["ok", "also ok"]


def test_json_reader_yields_nothing_for_malformed_single_json_file(tmp_path):
    path = tmp_path / "data.json"
    path.write_text("{not valid json")
    assert list(JsonReader().read_fragments(str(path))) == []


def test_json_reader_does_not_crash_on_adversarially_deep_nesting(tmp_path):
    """Regression test: `json.loads` itself parses very deep nesting fine
    (its C-accelerated decoder isn't bound by Python's recursion limit),
    but this reader's own `_walk` traversal is a plain recursive Python
    function and previously had no depth guard -- a 2,000-level-deep JSON
    array (trivial to construct, e.g. from a malformed or adversarial
    dataset file) raised an uncaught `RecursionError` and crashed the
    entire scan. It must now be skipped like any other unparseable file.
    """
    path = tmp_path / "deep.json"
    path.write_text("[" * 2000 + '"leaf"' + "]" * 2000)
    assert list(JsonReader().read_fragments(str(path))) == []
