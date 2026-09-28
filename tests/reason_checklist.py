"""Which test proves each named failure code (DESIGN Appendix B; IMPLEMENTATION_PLAN M0.9).

An entry is either ``"path::test_name"`` for a test that exists today, or ``"M<n> path::name"``
for a test name reserved for the milestone that makes the code reachable. When a milestone lands,
drop its prefix; ``tests/core/test_errors.py`` then checks that the test really exists.
"""

from qrp2p.core.errors import AdmitReason, CloseReason, FileCancelReason

CRYPTO = "tests/core/crypto"

CLOSE_REASONS: dict[CloseReason, str] = {
    CloseReason.NORMAL: "tests/core/test_record.py::test_close_normal_is_sent_and_received",
    CloseReason.DECRYPT_FAILED: f"{CRYPTO}/test_aead.py::test_wrong_sequence_number_is_decrypt_failed",
    CloseReason.UNEXPECTED_MESSAGE: "tests/core/test_handshake.py::test_every_invalid_message_in_every_state",
    CloseReason.OVERSIZE: "tests/core/test_wire.py::test_oversize_frame_rejected_before_allocation",
    CloseReason.SCHEMA_ERROR: f"{CRYPTO}/test_identity.py::test_decode_rejects_unknown_version",
    CloseReason.SIGNATURE_INVALID: f"{CRYPTO}/test_hybrid_sig.py::test_tampered_mldsa_half_is_rejected",
    CloseReason.FINISHED_INVALID: "tests/core/test_handshake.py::test_tampered_finished_is_rejected",
    CloseReason.PIN_MISMATCH: "tests/core/test_handshake.py::test_pin_mismatch_aborts_before_confirm",
    CloseReason.POLICY: f"{CRYPTO}/test_provider.py::test_plain_provider_refuses_profiles_it_was_not_built_with",
    CloseReason.TIMEOUT: "tests/core/test_handshake.py::test_handshake_deadline_expires",
    CloseReason.REPLACED: "M2 tests/services/test_session_manager.py::test_new_session_replaces_old",
    CloseReason.RATE_LIMITED: "M2 tests/services/test_transport.py::test_hello_rate_limit",
    CloseReason.INTERNAL: f"{CRYPTO}/test_provider.py::test_short_random_source_is_internal",
    CloseReason.LOCKED: "M2 tests/services/test_vault.py::test_lock_closes_sessions",
    CloseReason.KEM_FAILURE: f"{CRYPTO}/test_xwing.py::test_encapsulate_to_low_order_x25519_key_is_kem_failure",
    CloseReason.REFLECTION: "tests/core/test_handshake.py::test_own_bundle_is_reflection",
    CloseReason.INVALID_KEM_KEY: f"{CRYPTO}/test_xwing.py::test_mlkem_coefficient_not_below_q_is_invalid_kem_key",
}

ADMIT_REASONS: dict[AdmitReason, str] = {
    AdmitReason.NONE: "tests/core/test_handshake.py::test_accept_carries_reason_none",
    AdmitReason.DECLINED: "M2 tests/services/test_admission.py::test_blocked_contact_declined",
    AdmitReason.PROFILE_POLICY: "M2 tests/services/test_admission.py::test_profile_policy",
    AdmitReason.TIMEOUT: "M2 tests/services/test_admission.py::test_prompt_deadline",
    AdmitReason.BUSY: "M2 tests/services/test_admission.py::test_simultaneous_open_busy",
}

FILE_CANCEL_REASONS: dict[FileCancelReason, str] = {
    FileCancelReason.USER: "M2 tests/services/test_files.py::test_user_cancel_deletes_part_file",
    FileCancelReason.SIZE_MISMATCH: "M2 tests/services/test_files.py::test_size_mismatch_aborts",
    FileCancelReason.HASH_MISMATCH: "M2 tests/services/test_files.py::test_hash_mismatch_aborts",
    FileCancelReason.DISK_FULL: "M2 tests/services/test_files.py::test_disk_full_cancels",
    FileCancelReason.LIMIT: "M2 tests/services/test_files.py::test_size_limit_cancels",
}
