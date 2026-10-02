# UI mockup generation prompts

Generated with the built-in ImageGen tool. Every call used an opaque background
(`transparent_background: false`). File references below use repository filenames for
portability. The prompts are preserved as used, including instructions the model did not
fully satisfy; see [asset caveats](README.md#reading-the-images).

## messenger-light.png

No reference image.

```text
Use case: ui-mockup.
Create one high-fidelity polished widescreen desktop application mockup for QRP2P, a LAN-only two-person messenger with a hybrid post-quantum channel. This is a design exploration.
Visual direction: bold minimalist communication product, confident monochrome typography, warm ivory surfaces, ink-black text and primary actions, enormous breathing room, subtle warm-gray dividers, almost no boxes or ornamental chrome. Crisp Inter-like typography. Contemporary editorial restraint, no platform imitation. Avoid a standard full-height contacts sidebar: put a narrow horizontal contact strip underneath the application header, Alice selected and Bob offline, and let one roomy conversation occupy the centered main canvas. Rounded compact message bubbles, incoming soft warm gray, outgoing near-black with white text. Intentionally quiet and human.
Composition: one front-facing app window fills almost the whole landscape image with a tiny neutral margin. Header QRP2P at left, small Local network only status and Inspector action at right. Horizontal contacts row below it. A modest Alice conversation heading with Verified and Online. Two messages and a compact file attachment, with thoughtful whitespace and a broad minimal composer at the bottom. Inspector remains closed. No right-side panel.
Text, verbatim where used: "QRP2P", "Local network only", "Alice", "Bob", "Online", "Offline", "Verified", "Inspector", "Ready to test the handshake?", "Yes. Both laptops are on the same network.", "Delivered", "handshake-notes.pdf", "284 KB", "Accept file", "Message Alice…", "Send".
Constraints: realistic UI feasible in PySide6 / Qt Quick QML. No account login, groups, online service, voice calls or extra invented features. Do not claim the protocol is secure or production-ready. Small understated line icons only. No full-height sidebar, permanently open Inspector, colorful dashboard cards, neon colors, gradients, stock illustrations, giant locks, crypto coins, diagrams, laptop frame, hands, perspective tilt, marketing text or watermark. Clearly prioritize a focused conversation over data analysis.
```

## inspector-light.png

Reference: messenger-light.png, used as a style reference.

```text
Use case: ui-mockup.
Input image 1 is a STYLE REFERENCE: the user-selected minimal QRP2P messenger. Create a new widescreen high-fidelity desktop UI design study of the SAME application with Session Inspector opened. Preserve its warm ivory background, black text and restrained black controls, crisp typography, small gentle corners, elegant spacing, line icons and horizontal contacts. This is a concept screenshot with sample content, not an actual implemented app.
Primary request: normal messenger quietly becomes a beautiful functional cryptography workspace when the user opens Inspector. It must still feel clean and tasteful; richer content comes from useful protocol information.
Composition: front-facing application window nearly fills landscape image. Slim app header "QRP2P", subtle "Local network only", and "Close Inspector". Below, a much narrower chat pane at left (roughly one quarter of available width) shows "Alice", "Verified", a few compact messages and composer. The larger right workspace (roughly three quarters) is headed "Session Inspector", "Public trace", "Sample session". Use clearly defined tabs "Timeline", "Messages", "Keys", "Security".
Timeline tab is active: spacious vertical Alice → You exchange diagram with directional arrows for "Hello", "Reply", "Confirm", "Admit". Alice is initiator here, You is responder. Hello Alice→You; Reply You→Alice; Confirm Alice→You; Admit You→Alice. Include a few small measured timing labels explicitly sample. Selected Reply arrow has a muted accent and field detail adjacent or below. Details show "Reply", "HYBRID-1", and a precise small semantic field table: "nonce_R" offset "0" size "32 B"; "ct" offset "32" size "1120 B"; "ReplyInner (sealed)" offset "1152" with no invented size. Small hex excerpt with subtle selected-byte highlight, copy action and short useful field explanation "X-Wing ciphertext: ML-KEM-768 + X25519". At footer show "Secret values hidden in normal sessions". Plain labels and subtle pale green-blue selected marks, most surfaces neutral. No visible secret bytes.
Constraints: do not turn this into a full dark hacker tool. No fake scores, meaningless charts, KPI cards, giant locks, decorative circuit boards, simulated glowing particles, neon or stock illustrations. All panels should earn their place. Do not show decrypted ReplyInner or identity private keys. The exact UI text specified should be spelled correctly. No third-party branding, device photographs, perspective tilt or watermarks. Keep main app style clearly identifiable from reference while thoughtfully reflowing its layout to expose real protocol structure.
```

## attack-lab-light.png — initial generation

Reference: messenger-light.png, used as a style reference. The initial output was corrected before it was selected.

```text
Use case: ui-mockup.
Input image 1 is a STYLE REFERENCE: user-selected minimal QRP2P messenger. Create a new widescreen high-fidelity desktop UI design study for its Attack Lab workspace. SAME product typography, warm ivory palette, black text, gentle compact corners and restrained black controls. Learning content is rich and real, yet clean and calm.
Primary request: show exactly what happens when Mallory flips one bit of a ciphertext record between two simulated participants. This is a design study with illustrative sample bytes. Local lab is separate from real conversations.
Composition: one front-facing large desktop app window almost fills image. Header "QRP2P", followed by "Attack Lab" and a small clearly visible violet "LAB · Simulated identities" chip, with "Back to chat". Very subtle violet tint in lab canvas, mostly neutral ivory. Scenario picker compact at top: "Flip one bit in a record". Underneath, one dominant sequence diagram with Alice, Mallory and Bob on three vertical lanes. Alice sends a record to Mallory, Mallory changes a single byte, Bob receives altered ciphertext and rejects it at "ChaCha20-Poly1305 authentication". Use simple actual causal arrows, no decorative security imagery. One small violet mutation mark on Mallory; red confined to the rejection point.
A compact inline compare directly beneath selected record shows "Original" byte "7A" and "Modified" byte "7B", with one changed bit highlighted. Caption "XOR 0x01 · first ciphertext byte". Highlight only this alteration, not the entire hex table.
Bottom evidence panel with three concise factual lines: "Authentication failed", "Close reason: decrypt_failed", "Message not delivered". Optional small read-only original plaintext in Alice's simulated endpoint "hello", but Bob must not show this plaintext as received. Compact functional controls "Reset", "Step", "Run" with current stopped state "Stopped at authentication failure". Add a small tab/action "Inspect record" and selected detail "Record · Sample data".
Constraints: do not imply Mallory decrypted the record. No invented tamper_detected reason; use exact "decrypt_failed". No real contacts, accounts or real-session attacks. No giant padlocks, hack success animation, fictional security score, unnecessary KPI cards, red full-screen alarm, terminal wall, neon green, circuit artwork, laptop frame, photographic setting, dramatic perspective or watermarks. Practical QML-feasible 2D diagrams and data views. The app should look like a cohesive continuation of the minimal reference, with rich content replacing empty space.
```

## attack-lab-light.png — correction

Reference: the initial Attack Lab image, used as the edit target. Only the corrected output is included.

```text
Use case: precise-object-edit / ui-mockup technical annotation correction.
Edit the supplied QRP2P Attack Lab mockup. Preserve the entire layout, typography, warm ivory surfaces, violet lab indicators, arrows, panes and controls exactly. Correct ONLY these technical annotations:
1. Under Mallory replace "Passive modifier (simulated)" with "Active attacker (simulated)". Changing ciphertext is an active attack.
2. In the bottom-left Original byte pane the exact binary value for 7A must be "0111 1010". Highlight ONLY its final rightmost 0 with violet. In Modified pane 7B must be "0111 1011". Highlight ONLY its final rightmost 1 with violet. Those last bits are the ones changed by XOR 0x01. Both rows must have exactly 8 binary digits. Do not highlight the leading zero in either pane.
3. Remove invented exact ciphertext sizes: on the first arrow replace "296 bytes" with "Sample ciphertext"; on the second arrow replace "296 bytes (1 byte changed)" with "1 byte changed"; in the event log replace "Ciphertext: 296 bytes." with "Sample ciphertext." and "(296 bytes)" with "(sample record)".
Keep failure reason exact "decrypt_failed" and the message-not-delivered outcome. Preserve every other element and all style. This remains an illustrative UI mockup, not real measurements. No additional panels, visual redesign, or extra elements.
```

## messenger-dark.png

Reference: messenger-light.png, used as the edit target.

```text
Use case: ui-mockup / theme edit. Image 1 is the edit target. Make this exact minimal QRP2P messenger a polished dark-mode counterpart. Preserve all layout, labels, messages, contact strip, whitespace, icons and controls. Change only theme: neutral charcoal canvas #151718, raised surfaces #1D2022 and #24282A, off-white primary text #EFF1F2, legible secondary text #B3B7BA, subtle dividers #3A3F43. Outgoing bubble and primary buttons become off-white with dark text; incoming bubbles dark gray with light text. Keep verification/online marks restrained green. No blue neon, purple branding, gradients, shadows, added panels or new content. Use readable contrast for every label. Exact front-facing application screenshot, no outer device or scene, opaque background.
```

## inspector-dark.png

Reference: inspector-light.png, used as the edit target.

```text
Use case: ui-mockup / theme edit. Image 1 is the edit target. Make the supplied exact minimal QRP2P Session Inspector a polished dark-mode counterpart. Preserve layout, typography, all labels, timings, field offsets and sizes, diagrams and panes. Neutral charcoal canvas #151718, panel surfaces #1D2022 and #24282A, off-white text #EFF1F2, secondary text #B3B7BA, dividers #3A3F43. Primary button off-white with dark text. Selected Reply and selected ct field use a subtle blue-gray fill #253446 and muted light blue #91B4E8. Correct the selection relationship: ct is selected in the field table, so highlight ct row, not nonce_R; in hex excerpt highlight ciphertext bytes from offset 0020 onward, not byte at 0000. Preserve nonce_R offset0 size32B, ct offset32 size1120B, ReplyInner sealed offset1152 with unknown-size dash. Normal-session secret values remain hidden. No neon, hacker effects, gradients, added content or extra panels. All text and structural lines readable. Opaque front-facing screenshot.
```

## attack-lab-dark.png

Reference: attack-lab-light.png, used as the edit target.

```text
Use case: ui-mockup / theme edit. Image 1 is the edit target. Make this exact minimal QRP2P Attack Lab screenshot a polished dark-mode counterpart. Preserve every layout, label, causal diagram, controls and technical value. Neutral charcoal #151718 canvas, #1D2022/#24282A surfaces, #EFF1F2 main text and #B3B7BA secondary text, subtle dividers. Lab-specific canvas faint violet #2E273B with muted light violet #BEADF3 highlights. Failure point uses muted light red #EE9B9B on dark red tint #392329, confined to actual failure and its labels. Black primary button becomes off-white with dark text. Mallory remains 'Active attacker (simulated)'. Original 7A binary 0111 1010 highlights ONLY last0; modified 7B 0111 1011 highlights ONLY last1. Exact failure reason decrypt_failed, outcome Message not delivered. Retain sample ciphertext labels, no invented numeric ciphertext lengths. No neon, glowing effects, ornamental gradients, hacker-green terminal, extra panels or content. Readable high-contrast text throughout. Opaque front-facing application screenshot.
```


