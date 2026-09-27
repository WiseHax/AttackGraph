"""Strict comparability gates for analytical results."""



from app.analytics.policy import AnalysisPolicy, AnalysisPolicyV2, generate_policy_fingerprint





class ComparabilityError(ValueError):

    """Raised when an analytical comparison is attempted across incompatible domains."""

    pass





def verify_comparability(
    baseline_policy: AnalysisPolicy | AnalysisPolicyV2,
    target_policy: AnalysisPolicy | AnalysisPolicyV2,
) -> None:

    """Verify that two analytical policies define identically bounded domains.



    If the fingerprints mismatch, silent analytical comparison (e.g., risk reduction

    subtraction) is refused to prevent meaningless or corrupted metrics.

    """

    # Fail closed on unsupported policy types, and refuse v1/v2 comparison
    # explicitly rather than relying on the fingerprints happening to differ.
    for policy in (baseline_policy, target_policy):
        if not isinstance(policy, (AnalysisPolicy, AnalysisPolicyV2)):
            raise ComparabilityError(
                f"Unsupported analytical policy type: {type(policy).__name__}"
            )
    if type(baseline_policy) is not type(target_policy):
        raise ComparabilityError(
            f"Incompatible analytical policy versions: "
            f"baseline={baseline_policy.version}, target={target_policy.version}"
        )

    baseline_fp = generate_policy_fingerprint(baseline_policy)

    target_fp = generate_policy_fingerprint(target_policy)



    if baseline_fp != target_fp:

        raise ComparabilityError(

            f"Incompatible analytical policies. Fingerprint mismatch: "

            f"baseline={baseline_fp}, target={target_fp}"

        )
