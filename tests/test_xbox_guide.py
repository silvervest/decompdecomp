"""What the Xbox guide tells agents about link-time code generation, checked against what Burnout 3's helpers ran
into."""

from decompnet.app import tools


def _xbox() -> str:
    return " ".join(tools.guide_text("xbox", "xbox").split())


def test_float_constants_try_the_literal_and_the_extern():
    """The guide said "write 0.5f, not extern const float D_..."; an agent following it scored 59.1% where externs
    gave 65.8%."""
    text = _xbox()
    assert "try both forms" in text and "On equal scores prefer the literal" in text
    assert "`1.0f - 1.3f`" in text
    assert "not `extern const float" not in text
