"""WCAG 2.2 AA contrast of the colour pairs the components actually compose (UI_DESIGN §4.2).

The tokens are read from Theme.qml itself, so a palette change that breaks a pairing fails here.
Text needs 4.5:1; essential non-text marks (control boundaries, focus, the online dot) need 3:1.
Decorative dividers and disabled controls are exempt, as WCAG allows.
"""

import re
from pathlib import Path

import pytest

import qrp2p.ui

THEME = (Path(qrp2p.ui.__file__).parent / "qml" / "Qrp2p" / "Theme" / "Theme.qml").read_text(
    encoding="utf-8"
)
TOKEN = re.compile(
    r'readonly property color (\w+): dark \? "(#[0-9A-Fa-f]{6})" : "(#[0-9A-Fa-f]{6})"'
)
TOKENS = {name: {"dark": dark, "light": light} for name, dark, light in TOKEN.findall(THEME)}

TEXT = 4.5
NON_TEXT = 3.0

# (foreground, background, minimum): every pairing used for text or essential marks.
PAIRS = [
    ("text", "canvas", TEXT),
    ("text", "surface", TEXT),
    ("text", "surfaceSubtle", TEXT),
    ("text", "hoverFill", TEXT),
    ("text", "pressedFill", TEXT),
    ("text", "avatarFill", TEXT),
    ("textSecondary", "canvas", TEXT),
    ("textSecondary", "surface", TEXT),
    ("textSecondary", "surfaceSubtle", TEXT),
    ("textSecondary", "hoverFill", TEXT),
    ("primaryText", "primaryFill", TEXT),
    ("primaryText", "primaryHover", TEXT),
    ("selectionText", "selectionFill", TEXT),
    ("exposureText", "exposureFill", TEXT),
    ("exposureText", "canvas", TEXT),
    ("labText", "labFill", TEXT),
    ("dangerText", "dangerFill", TEXT),
    ("dangerText", "canvas", TEXT),
    ("dangerText", "surface", TEXT),
    ("dangerText", "surfaceSubtle", TEXT),
    ("success", "canvas", TEXT),
    ("success", "surface", TEXT),
    ("success", "surfaceSubtle", TEXT),
    ("controlBoundary", "surface", NON_TEXT),
    ("controlBoundary", "canvas", NON_TEXT),
    ("focus", "canvas", NON_TEXT),
    ("focus", "surface", NON_TEXT),
    ("online", "canvas", NON_TEXT),
    ("online", "surfaceSubtle", NON_TEXT),
    ("exposureText", "canvas", NON_TEXT),  # the glass-box frame
]


def luminance(color: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(a: str, b: str) -> float:
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_the_theme_defines_every_token_in_both_schemes() -> None:
    assert len(TOKENS) >= 20
    for foreground, background, _ in PAIRS:
        assert foreground in TOKENS, foreground
        assert background in TOKENS, background


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize(("foreground", "background", "minimum"), PAIRS)
def test_contrast(scheme: str, foreground: str, background: str, minimum: float) -> None:
    measured = ratio(TOKENS[foreground][scheme], TOKENS[background][scheme])
    assert measured >= minimum, f"{foreground} on {background} ({scheme}): {measured:.2f}"


def test_the_measure_matches_wcag_examples() -> None:
    assert ratio("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert ratio("#767676", "#FFFFFF") == pytest.approx(4.54, abs=0.01)
