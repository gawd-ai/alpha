//! ADR-0041 clustered-boot posture. The transport publishes an `OriginVerdict` for every peer frame
//! but does not enforce it; enforcement is an injected topic consumer such as `policy-origin`. A
//! clustered composition with none wired admits forged-signature frames, so the composition roots
//! warn loudly at boot. This pins `omni::warn_if_no_origin_defense`: it warns when the caller reports
//! no wired policy and is silent when the composition explicitly reports one.

use omni::warn_if_no_origin_defense;

#[test]
fn warns_when_no_origin_defense_is_wired_and_is_silent_once_one_is() {
    assert!(
        warn_if_no_origin_defense(false),
        "no origin defense wired → the clustered-boot posture check must warn"
    );

    assert!(
        !warn_if_no_origin_defense(true),
        "a composition that wired origin defense must not warn"
    );
}
