# Roadmap after v1

The public v1 reference journey is implemented. Production deployments still
need independently operated machines and regions, a reviewed relay, authority
rotation and guardian operations, real confidential-compute adapters with
vendor evidence, chosen payment-rail adapters, observability, abuse response,
desktop code signing/notarization/updates and an independent cryptography and
recovery audit.

Those integrations are deliberately not simulated as completed. Each should be
introduced behind the published adapter boundary with test vectors, rollback
instructions and a deployment-specific threat model.
