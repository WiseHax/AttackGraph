"""Strict comparability gates for analytical results."""



from app.analytics.policy import AnalysisPolicy, generate_policy_fingerprint





class ComparabilityError(ValueError):

    """Raised when an analytical comparison is attempted across incompatible domains."""

    pass





def verify_comparability(baseline_policy: AnalysisPolicy, target_policy: AnalysisPolicy) -> None:

    """Verify that two analytical policies define identically bounded domains.



    If the fingerprints mismatch, silent analytical comparison (e.g., risk reduction

    subtraction) is refused to prevent meaningless or corrupted metrics.

    """

    baseline_fp = generate_policy_fingerprint(baseline_policy)

    target_fp = generate_policy_fingerprint(target_policy)



    if baseline_fp != target_fp:

        raise ComparabilityError(

            f"Incompatible analytical policies. Fingerprint mismatch: "

            f"baseline={baseline_fp}, target={target_fp}"

        )
