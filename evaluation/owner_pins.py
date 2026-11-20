"""Coordinator-approved evaluation input overrides; never edit fixture sources."""
RAUTHY_PIN = '01375efb2a14692a7977f2f8aa60121f3fcc2f01'


def configure_rauthy():
    import rauthy
    # The acceptance harness stays pinned. Override only the owner input revision
    # used by its unchanged build/provenance checks and runtime evidence.
    assert rauthy.REVISION in ('1e114b84b01988bf15306b110b040378878488d3', RAUTHY_PIN)
    rauthy.REVISION = RAUTHY_PIN
