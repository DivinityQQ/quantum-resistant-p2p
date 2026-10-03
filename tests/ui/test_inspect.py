"""The Inspector's evidence builders on real traces (UI_DESIGN §7, §10): no Qt involved."""

import itertools
import re
from pathlib import Path

import pytest

from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import Direction, FrameTraced, RecordTraced, SessionClosed, StateChanged
from qrp2p.core.wire import Chat, Frame, FrameType, encode_inner
from qrp2p.ui.inspect import fields, keygraph, security, spec
from qrp2p.ui.inspect.model import ProfileFacts, RecordOpened, Revealed, TraceItem
from qrp2p.ui.inspect.timeline import Timeline, TimelineRow
from tests.ui.inspect_support import profile_facts, scripted, session_facts

DESIGN = (Path(__file__).parents[2] / "docs" / "v2" / "DESIGN.md").read_text(encoding="utf-8")


# --- spec links -------------------------------------------------------------------------------------


def test_every_cited_section_is_a_heading_of_the_design() -> None:
    headings = {line.lstrip("#").strip() for line in DESIGN.splitlines() if line.startswith("#")}
    for section, title in spec.SECTIONS.items():
        top = spec._TOP.get(section)
        assert (top or f"{section} {title}") in headings, section


def test_anchors_follow_githubs_rules() -> None:
    assert spec.anchor("7.2") == "#72-message-layouts"
    assert spec.anchor("4.3") == "#43-x25519-kem-lab-classical-only"
    assert spec.anchor("4") == "#4-cryptographic-profiles"
    assert spec.anchor("Appendix B") == "#appendix-b--codes"
    assert spec.link("8.1").endswith("DESIGN.md#81-records")
    assert (spec.cite("7.4"), spec.cite("Appendix B")) == ("DESIGN §7.4", "DESIGN Appendix B")


def cited_sections() -> set[str]:
    run = scripted(exposed=True)
    graph = keygraph.build(run.i.items, session_facts(exposed=True))
    facts = security.build(run.i.items, session_facts())
    return (
        {e.section for e in fields.EXPLANATIONS.values()}
        | {n.section for n in graph.nodes}
        | {f.section for f in facts}
    )


def test_every_explanation_cites_a_known_section() -> None:
    assert cited_sections() <= set(spec.SECTIONS)


# --- fields -----------------------------------------------------------------------------------------


def frames(items: list[TraceItem]) -> list[tuple[int, FrameTraced]]:
    return [(i.ordinal, i.event) for i in items if isinstance(i.event, FrameTraced)]


def frame_of(items: list[TraceItem], kind: FrameType, direction: Direction) -> FrameTraced:
    return next(f for _, f in frames(items) if f.frame.type is kind and f.direction is direction)


def test_reply_fields_carry_frame_and_body_offsets() -> None:
    """UI_DESIGN §7.3's worked example: a HYBRID-1 Reply."""
    reply = frame_of(scripted().i.items, FrameType.REPLY, Direction.IN)
    rows = {r.key: r for r in fields.frame_fields(reply)}
    assert (rows["h:length"].value, rows["h:type"].value) == ("9,150 B", "0x11 Reply")
    expected = {
        "b:nonce_R": (5, 0, 32),
        "b:ct": (37, 32, 1120),
        "b:ct/ctM": (37, 32, 1088),
        "b:ct/ctX": (37 + 1088, 32 + 1088, 32),
        "b:ReplyInner (sealed)": (1157, 1152, 7998),
        "b:ReplyInner (sealed)/tag": (1157 + 7982, 1152 + 7982, 16),
    }
    for key, (start, body_offset, length) in expected.items():
        assert (rows[key].start, rows[key].body_offset, rows[key].length) == (
            start,
            body_offset,
            length,
        ), key
    assert rows["b:ct/ctM"].depth == 1
    assert all(r.explanation and r.section and r.origin == fields.WIRE for r in rows.values())
    whole = reply.frame.encode()
    assert whole[rows["b:nonce_R"].start : rows["b:nonce_R"].start + 32] == reply.frame.body[:32]


def test_hello_values_are_read_off_the_bytes() -> None:
    hello = frame_of(scripted(exposed=True).i.items, FrameType.HELLO, Direction.OUT)
    rows = {r.name: r for r in fields.frame_fields(hello)}
    assert (rows["version"].value, rows["profile"].value) == ("0x02", "HYBRID-1")
    assert rows["flags"].value == "gb_request = 1"
    assert (rows["pkM"].length, rows["pkX"].length) == (1184, 32)


def test_a_frame_of_the_wrong_size_stays_one_unsplit_field() -> None:
    odd = FrameTraced(Direction.IN, Frame(FrameType.REPLY, b"xx"), (fields.Field("body", 0, 2),))
    rows = fields.frame_fields(odd)
    assert [r.name for r in rows] == ["length", "type", "body"]
    assert "Not split" in rows[-1].explanation
    supported = FrameTraced(
        Direction.IN,
        Frame(FrameType.PROFILE_UNSUPPORTED, b"\x03"),
        (fields.Field("supported", 0, 1),),
    )
    assert fields.frame_fields(supported)[-1].value == "HYBRID-1, PQ-CNSA-1"
    assert fields.explain("nothing such") == fields.Explanation("", "")


def opened(items: list[TraceItem], key: str, seq: int) -> RecordOpened:
    return next(
        i.event
        for i in items
        if isinstance(i.event, RecordOpened) and (i.event.key, i.event.seq) == (key, seq)
    )


def test_an_exposed_handshake_frame_shows_what_it_held() -> None:
    items = scripted(exposed=True).i.items
    profile = profile_facts()
    reply = fields.plaintext_fields(FrameType.REPLY, opened(items, "hs_R.key", 0), profile)
    assert [r.name for r in reply] == ["nonce", "IdR", "SigR", "FinR"]
    assert [r.length for r in reply[1:]] == [4577, profile.sig_len, profile.hash_len]
    assert all(r.origin == fields.DECRYPTED and r.source == "plaintext" for r in reply)
    admit = fields.plaintext_fields(FrameType.ADMIT, opened(items, "hs_R.key", 1), profile)
    assert [(r.name, r.value) for r in admit[1:4]] == [
        ("decision", "accept"),
        ("admit flags", "glass_box = 1"),
        ("reason", "none"),
    ]
    assert fields.HANDSHAKE_KEYS[FrameType.ADMIT] == ("hs_R.key", 1)


def test_a_layout_that_does_not_fit_shows_no_guess() -> None:
    weird = RecordOpened("hs_R.key", 0, b"n" * 12, b"too short", opened=True)
    assert [r.name for r in fields.plaintext_fields(FrameType.REPLY, weird, profile_facts())] == [
        "nonce"
    ]
    assert len(fields.plaintext_fields(FrameType.REPLY, weird, None)) == 1


def test_an_exposed_record_is_decoded_with_peer_text_made_safe() -> None:
    items = scripted(exposed=True).r.items
    record = next(
        i.event
        for i in items
        if isinstance(i.event, RecordTraced)
        and i.event.kind == "chat"
        and i.event.direction.value == "in"
    )
    key = fields.record_key(record, initiator=False)
    assert key == "ap_I[0].key"
    rows = {
        r.name: r for r in fields.plaintext_fields(FrameType.RECORD, opened(items, key, 0), None)
    }
    assert rows["kind"].value == "chat"
    assert rows["text"].value == "hello 0"
    assert rows["id"].value.endswith("(16 B)")
    hostile = RecordOpened("k", 0, b"", b"\x81\xa4kind\xa4chat", opened=True)  # no id, no text
    assert [r.name for r in fields.plaintext_fields(FrameType.RECORD, hostile, None)] == [
        "nonce",
        "Inner",
    ]  # not a valid Inner: the bytes, no fields
    override = "a\u202eb"
    sneaky = RecordOpened("k", 0, b"", encode_inner(Chat(id=bytes(16), text=override)), opened=True)
    text = {r.name: r for r in fields.plaintext_fields(FrameType.RECORD, sneaky, None)}["text"]
    assert text.value == "a\ufffdb"


@pytest.mark.parametrize(
    ("direction", "generation", "initiator", "expected"),
    [
        (Direction.OUT, 0, True, "ap_I[1].key"),
        (Direction.IN, 0, True, "ap_R[1].key"),
        (Direction.OUT, 2, False, "ap_R[1]+2.key"),
        (Direction.IN, 3, False, "ap_I[1]+3.key"),
    ],
)
def test_record_keys_follow_roles(
    direction: Direction, generation: int, initiator: bool, expected: str
) -> None:
    record = RecordTraced(direction, 1, generation, 0, 30, "chat")
    assert fields.record_key(record, initiator=initiator) == expected


# --- timeline ---------------------------------------------------------------------------------------


def built(items: list[TraceItem], *expanded: str) -> tuple[TimelineRow, ...]:
    timeline = Timeline()
    timeline.extend(items)
    return timeline.rows(expanded)


def test_the_handshake_reads_as_a_sequence_of_frames_and_states() -> None:
    rows = built(scripted().i.items)
    head = [(r.kind, r.title, r.direction) for r in rows[:7]]
    assert head[0] == ("schedule", "Key schedule", "")  # dk derived before Hello
    assert ("frame", "Hello", "out") in head
    titles = [r.title for r in rows if r.kind == "frame"]
    assert titles[:4] == ["Hello", "Reply", "Confirm", "Admit"]
    assert [r.direction for r in rows if r.kind == "frame"][:4] == ["out", "in", "out", "in"]
    assert any(r.title == "Initiator: established" for r in rows)
    assert rows[0].time == 0.0
    assert all(b.time >= a.time for a, b in itertools.pairwise(rows))


def test_ordinary_records_collapse_and_control_records_stand_alone() -> None:
    rows = built(scripted().i.items)
    groups = [r for r in rows if r.kind == "group"]
    assert groups
    first = groups[0]
    assert first.title.startswith("Records · chat")
    assert first.count >= 6  # three chats each way and their receipts
    assert "out" in first.detail
    control = [r.title for r in rows if r.kind == "record"]
    assert "Record · key_update" in control
    assert {"Record · rekey_offer", "Record · rekey_finish", "Record · rekey_switch"} <= set(
        control
    )
    # Closing queues the close record, which is sealed after the close is traced.
    assert [(r.kind, r.title, r.tone) for r in rows[-2:]] == [
        ("closed", "Closed: normal", ""),
        ("record", "Record · close", "accent"),
    ]


def test_an_expanded_group_lists_its_records() -> None:
    items = scripted().i.items
    timeline = Timeline()
    timeline.extend(items)
    group = next(r for r in timeline.rows() if r.kind == "group")
    members = timeline.members(group.key)
    assert len(members) == group.count
    assert all(m.member and m.kind == "record" and m.frame >= 0 for m in members)
    expanded = timeline.rows([group.key])
    at = expanded.index(group)
    assert expanded[at + 1 : at + 1 + group.count] == members


def test_building_incrementally_gives_the_same_rows() -> None:
    items = scripted().r.items
    once = built(items)
    timeline = Timeline()
    for n in range(0, len(items), 7):
        timeline.extend(items[n : n + 7])
        timeline.extend(items[: n // 2])  # repeats are ignored
    assert timeline.rows() == once


def test_evicted_events_show_as_a_gap() -> None:
    items = scripted().i.items
    kept = items[:40] + items[90:]
    rows = built(kept)
    gap = next(r for r in rows if r.kind == "gap")
    assert (gap.first, gap.last, gap.count) == (40, 89, 50)
    assert gap.title == "Earlier events no longer retained"
    late = built(items[10:])
    assert late[0].kind == "gap"
    assert late[0].count == 10


def test_a_record_that_fails_to_open_is_shown_unopened_then_the_failure() -> None:
    frame = Frame(FrameType.RECORD, bytes(40))
    items = [
        TraceItem(0, 1.0, FrameTraced(Direction.IN, frame, ())),
        TraceItem(1, 1.5, SessionClosed(CloseReason.DECRYPT_FAILED, None, by_peer=False)),
    ]
    rows = built(items)
    assert [(r.kind, r.title) for r in rows] == [
        ("frame", "Record (not opened)"),
        ("closed", "Closed: decrypt_failed"),
    ]
    assert rows[1].tone == "danger"
    pending = built(items[:1])
    assert pending[0].title == "Record (not opened)"
    refusal = built(
        [TraceItem(0, 0.0, SessionClosed(CloseReason.POLICY, AdmitReason.BUSY, by_peer=False))]
    )
    assert (refusal[0].title, refusal[0].tone) == ("Closed: policy (busy)", "")


def test_revealed_values_are_not_timeline_rows() -> None:
    plain = built(scripted().i.items)
    exposed = built(scripted(exposed=True).i.items)
    assert [r.title for r in plain] == [r.title for r in exposed]


# --- key graph --------------------------------------------------------------------------------------


def nodes(graph: keygraph.KeyGraph) -> dict[str, keygraph.KeyNode]:
    return {n.key: n for n in graph.nodes}


def test_a_normal_session_shows_names_and_sizes_but_no_value() -> None:
    graph = keygraph.build(scripted().i.items, session_facts())
    found = nodes(graph)
    expected = {
        "dk", "ssM", "ssX", "ss", "hs", "hs_R", "hs_I", "fk_R", "fk_I", "hs_R.key", "derived[0]",
        "cs_0", "ap_I[0]", "ap_R[0]", "exporter_0", "derived[1]", "ap_I[0]+1", "ap_R[0]+1.iv",
        "dk[1]", "ss[1]", "cs_1", "ap_I[1]", "exporter_1", "th_hello", "th_final", "th_rekey[1]",
    }  # fmt: skip
    assert expected <= set(found)
    secrets = [n for n in graph.nodes if n.kind != "hash"]
    assert all(n.state == "observed" and n.value == "" for n in secrets)
    assert all(n.size > 0 for n in secrets if not n.key.startswith("dk"))
    assert found["th_hello"].state == "observed"
    assert len(found["th_hello"].value) == 64  # a public digest, in hex
    assert found["hs_R"].inputs == ("hs", "th_hello")
    assert found["cs_1"].inputs == ("derived[1]", "ss[1]")
    assert found["ap_I[0]+1"].inputs == ("ap_I[0]",)
    assert found["ap_I[1]"].inputs == ("cs_1", "th_rekey[1]")
    assert found["ss"].inputs == ("ssM", "ssX")
    assert found["ssM"].inputs == ("dk",)  # the initiator decapsulates
    assert found["hs_R.iv"].size == 12


def test_the_responder_encapsulates_and_has_no_decapsulation_key() -> None:
    found = nodes(keygraph.build(scripted().r.items, session_facts(initiator=False)))
    assert "dk" not in found
    assert found["ssM"].inputs == ()
    assert "Encaps" in found["ssM"].operation


def test_releases_are_lifecycle_facts_on_the_nodes() -> None:
    found = nodes(keygraph.build(scripted().i.items, session_facts()))
    assert found["dk"].released == "used"
    assert found["hs"].released == "handshake_done"
    assert found["cs_0"].released == "used"
    assert found["derived[0]"].released == "used"
    assert found["ap_I[0]"].released == "replaced"
    assert found["derived[1]"].released == "epoch_done"
    assert found["ap_I[1]"].released == ""  # still the current send key at the close


def test_an_exposed_session_shows_the_revealed_values() -> None:
    run = scripted(exposed=True)
    revealed = {i.event.label: i.event.value for i in run.i.items if isinstance(i.event, Revealed)}
    found = nodes(keygraph.build(run.i.items, session_facts(exposed=True, glass_box=True)))
    for name in ("dk", "ss", "hs", "cs_0", "ap_R[1]", "ap_I[0]+1.key", "derived[1]", "ssX[1]"):
        assert found[name].state == "revealed", name
        assert found[name].value == revealed[name].hex(), name


def test_evicted_inputs_are_marked_unavailable() -> None:
    items = scripted().i.items
    rekey = next(n for n, i in enumerate(items) if getattr(i.event, "step", "") == "offer")
    late = items[rekey:]
    found = nodes(keygraph.build(late, session_facts()))
    assert found["ap_I[1]"].state == "observed"
    assert any(n.state == "unavailable" for n in found.values())
    unavailable = [n for n in found.values() if n.state == "unavailable"]
    assert all(n.ordinal == -1 and n.value == "" for n in unavailable)


def test_a_handshake_in_progress_shows_what_comes_next_from_the_spec() -> None:
    items = scripted().r.items
    first_state = next(n for n, i in enumerate(items) if isinstance(i.event, StateChanged))
    hello_only = items[: first_state + 1]
    facts = session_facts(initiator=False, established=False)
    found = nodes(keygraph.build(hello_only, facts))
    assert found["cs_0"].state == "spec"
    assert found["ap_I[0]"].state == "spec"
    assert found["th_final"].state == "spec"
    assert found["hs"].state == "observed"


def test_layout_puts_inputs_left_of_what_they_feed() -> None:
    graph = keygraph.build(scripted().i.items, session_facts())
    found = nodes(graph)
    for node in graph.nodes:
        for source in node.inputs:
            assert found[source].column < node.column, (source, node.key)
    positions = {(n.column, n.row) for n in graph.nodes}
    assert len(positions) == len(graph.nodes)  # no two nodes on one spot
    assert graph.columns == 1 + max(n.column for n in graph.nodes)
    assert graph.rows == 1 + max(n.row for n in graph.nodes)
    assert {(e.source, e.target) for e in graph.edges} == {
        (s, n.key) for n in graph.nodes for s in n.inputs
    }
    epoch_1 = [n for n in graph.nodes if n.epoch == 1]
    assert min(n.row for n in epoch_1) > max(n.row for n in graph.nodes if n.epoch == 0)


def test_unknown_names_are_not_part_of_the_graph() -> None:
    assert keygraph.spec_of("kem.seed", session_facts()) is None
    assert keygraph.spec_of("plaintext", session_facts()) is None


def test_the_profile_shapes_the_kem_nodes() -> None:
    lab = session_facts(profile=ProfileFacts(**vars_of_lab()))  # type: ignore[arg-type]
    found = keygraph.spec_of("ss", lab)
    assert found is not None
    assert found.inputs == ("ssX",)
    assert "x25519kem" in found.operation


def vars_of_lab() -> dict[str, object]:
    base = profile_facts()
    return {
        "name": "LAB-CLASSICAL",
        "kem": "X25519-KEM",
        "signature": "Ed25519",
        "aead": base.aead,
        "hash": base.hash,
        "hash_len": 32,
        "sig_len": 64,
        "ek_len": 32,
        "ct_len": 32,
        "ek_parts": (),
        "ct_parts": (),
        "lab_only": True,
    }


# --- security ---------------------------------------------------------------------------------------


def facts_by_key(items: list[TraceItem], **changes: object) -> dict[str, security.Fact]:
    return {f.key: f for f in security.build(items, session_facts(**changes))}


def test_a_pinned_initiator_session_states_its_facts_and_their_evidence() -> None:
    found = facts_by_key(scripted().i.items)
    assert found["profile"].value.startswith("HYBRID-1: X-Wing")
    assert "ML-KEM-768 or X25519" in found["profile"].assumption
    assert found["identity"].status == "ok"
    assert "pinned" in found["identity"].value
    assert found["identity"].ordinal >= 0
    assert (found["verification"].status, found["verification"].value) == (
        "warn",
        "Safety number not compared",
    )
    assert found["exposure"].value == "Public trace"
    assert found["completion"].value == "Complete: Admit verified"
    assert found["keys"].value == "2 KeyUpdates (1 sent, 1 received), 1 PQ rekey completed"
    assert found["closed"].status == "info"
    assert not any(re.search(r"\d+ ?%", f.value) for f in found.values())  # never a score


def test_first_contact_and_verified_contacts_differ() -> None:
    items = scripted().i.items
    first = facts_by_key(items, pinned_before=False)
    assert first["identity"].status == "warn"
    assert "First contact" in first["identity"].value
    verified = facts_by_key(items, trust="verified")
    assert verified["verification"].status == "ok"


def test_the_responder_waits_for_key_confirmation() -> None:
    items = scripted().r.items
    complete = facts_by_key(items, initiator=False)
    assert complete["completion"].value == "Complete: key confirmation received"
    end_of_handshake = next(
        n for n, i in enumerate(items) if getattr(i.event, "state", "") == "established"
    )
    waiting = facts_by_key(items[: end_of_handshake + 1], initiator=False)
    assert waiting["completion"].value == "Admitted; waiting for key confirmation"


def test_exposure_and_failures_are_named() -> None:
    items = scripted().i.items
    assert facts_by_key(items, glass_box=True)["exposure"].status == "warn"
    assert "declined" in facts_by_key(items, glass_box_requested=True)["exposure"].value
    assert facts_by_key(items, lab=True)["verification"].value.startswith("Lab identities")
    failed = [
        TraceItem(0, 0.0, SessionClosed(CloseReason.DECRYPT_FAILED, None, by_peer=True)),
    ]
    found = facts_by_key(failed, established=False, ended=True, peer_short_id="")
    assert (found["closed"].title, found["closed"].status) == ("Authentication failed", "fail")
    assert "reported by the peer" in found["closed"].value
    assert found["completion"].status == "fail"
    assert found["identity"].value == "Not authenticated"
    lost = facts_by_key([], established=False, ended=True)
    assert lost["closed"].title == "Connection lost"
