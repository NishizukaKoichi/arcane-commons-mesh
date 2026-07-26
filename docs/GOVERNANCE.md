# Governance

v0.1 provides simple one-member-one-vote proposals. An active member has one
current vote per proposal. Casting again replaces the counted choice while every
cast remains in the append-only audit history.

The default quorum is 20% of active members. The default threshold is a simple
majority of yes/no votes; abstentions count for participation but not the
threshold denominator. Storage capacity, credit, donations, and equipment never
change vote weight.

Proposal results never automatically execute destructive or security-sensitive
configuration. An administrator must review and apply a change separately, and
that action is audited.
