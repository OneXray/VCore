# Exact configuration and in-memory TLS assertion identities for N7.
TESTS = {
    "n7_ech_config": [
        "static_ech_builds_both_tls_backends_without_dns_or_io",
        "static_ech_is_strict_and_never_enables_dynamic_lookup",
        "unsupported_ech_configs_fail_at_parse_before_a_client_can_emit_inner_sni",
        "ech_selection_skips_unknown_or_mandatory_configs_and_keeps_exact_supported_bytes",
        "download_ech_inherits_replaces_or_clears_as_a_whole",
        "ech_is_standard_tls_only_with_explicit_download_clear_and_dns_inner_name",
    ],
    "n7_ech_tls": [
        "rejected_or_wrong_key_ech_never_reaches_application_data_even_with_a_matching_pin",
        "client_identity_is_sent_only_after_ech_acceptance",
        "cancelled_ech_emits_only_public_sni_and_releases_io_for_every_backend",
        "each_backend_and_hpke_suite_requires_real_ech_acceptance_before_data",
    ],
    "n7_encryption_config": [
        "public_encryption_accepts_all_six_modes_without_exposing_key_material",
        "vision_encryption_is_independent_of_outer_tls_but_keeps_transport_and_udp_limits",
    ],
    "n7_reality_config": [
        "public_reality_accepts_explicit_hybrid_without_replacing_the_fingerprint",
        "public_reality_rejects_profiles_without_the_required_hybrid_share",
        "download_inherits_or_replaces_the_entire_reality_object_without_leaf_merging",
        "hybrid_flag_is_a_strict_nonnullable_boolean_on_both_legs",
        "classic_default_and_explicit_false_preserve_all_existing_profiles",
        "inherited_profile_is_validated_after_download_reality_replacement",
        "hybrid_reality_cannot_be_combined_with_h3_or_plaintext_on_either_leg",
    ],
    "n7_jls_config": [
        "public_jls_builds_an_authenticated_security_client_without_exposing_credentials",
        "independent_download_inherits_jls_identity_and_applies_its_own_tls_fields",
        "download_jls_credentials_are_replaced_as_a_whole_or_explicitly_cleared",
        "malformed_or_partial_credentials_never_inherit_a_missing_secret",
        "invalid_jls_objects_do_not_echo_credentials_in_public_configuration_errors",
        "jls_rejects_incompatible_security_at_configuration_time",
        "download_security_switch_requires_explicit_clearing_of_inherited_identity",
        "selected_profiles_build_jls_without_changing_its_identity",
        "cancelled_jls_handshakes_release_supplied_io_and_never_reuse_randoms",
        "jls_security_client_rejects_ordinary_tls_before_application_data",
    ],
}
