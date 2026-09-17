# Contributing to this ArcRelay component

The [ArcRelay contribution and license agreement policy](https://github.com/ArcRelayProject/arcrelay/blob/main/CONTRIBUTING.md)
applies to this shared component. Keep contributions within the public desktop
and shared-library boundary; private mobile code and secrets must stay private.

## Trusted maintainer automation

This repository adopts the maintainer policy approved in
[ArcRelay PR #39](https://github.com/ArcRelayProject/arcrelay/pull/39).
PR authors `zibo-chen` (GitHub account ID `58510061`) and `chenzibo`
(`18285974`) receive automated review and protected auto-merge. They do not
require manual CLA labeling. This exception does not sign an agreement or
represent that a signed agreement was verified.

Only default-branch policy code runs with review and merge permissions. Approval
is bound to the exact PR head. Existing CI, CodeQL where configured, branch
freshness, conversation resolution, and branch protections remain in force.
Other contributors retain manual review and verified CLA labeling.

Run the component's Rust checks and `python3 -m unittest discover -s .github/scripts
-p 'test_*.py'` before changing this policy. Full packaging belongs in CI.
