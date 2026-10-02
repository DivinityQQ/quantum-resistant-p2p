# UI mockup assets

These six images accompany [UI_DESIGN.md](../../UI_DESIGN.md). They are generated design
references, not screenshots of a running PySide6 application. Light direction agreed and
dark counterparts added on 2026-10-02 using the built-in ImageGen tool, not the fallback CLI.
The images live in the repository so documentation does not depend on a chat or local cache.

| Asset | Role | Input |
| --- | --- | --- |
| [messenger-light.png](messenger-light.png) | Selected minimal messenger direction | New image from prompt |
| [inspector-light.png](inspector-light.png) | Same product with Inspector open | Minimal messenger as style reference |
| [attack-lab-light.png](attack-lab-light.png) | Isolated bit-flip experiment | Minimal messenger as style reference; corrected technical annotations |
| [messenger-dark.png](messenger-dark.png) | Dark messenger | Edit of corresponding light image |
| [inspector-dark.png](inspector-dark.png) | Dark Inspector | Edit of light Inspector, including ciphertext-selection correction |
| [attack-lab-dark.png](attack-lab-dark.png) | Dark lab | Edit of corrected light lab |

Generation prompts are preserved in [PROMPTS.md](PROMPTS.md). Earlier native-style, dark
workbench and HTML directions are not selected and are not normative references.

## Reading the images

- Follow the guide's tokens, accessible geometry and written interaction contracts rather than
  copying pixels. The wordmark is oversized; app branding assets remain to be finalized.
- Sample clocks, ciphertext and run state are illustrative. Produce real UI values from
  services/traces/controllers and real visual regression fixtures from tests.
- The light Inspector's selected nonce and ciphertext explanation do not agree. The dark edit
  selects ct and its visible bytes but still retains a small visual cue at byte 0000. Actual
  selected ranges and explanations must be synchronized; neither image is a selection fixture.
- The sealed ReplyInner size dash is a mockup omission. Actual captured length is available
  for a valid frame and should be displayed.
- Attack Lab images show Step/Run as visually active after a terminal authentication failure.
  Actual controls must be disabled there, with Reset available to start a new run.
- The lab shows byte 7A → 7B as an example of XOR 0x01; the last bit changes. The implementation
  shows the actual injected intervention and actual failure, not a predetermined outcome.
- These assets introduce no runtime fonts/icons/licenses. Bundle the licensed Inter and Lucide
  assets independently; do not extract or reuse generated icon pixels as application resources.

For revisions, keep the light/dark pair's structure consistent, save a new sibling version
before replacement, review technical annotations, and update guide/manifest/prompts together.
