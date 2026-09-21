# Working on auth-ldap

NAF is a small PHP framework with optional Composer plugins. Its core owns boot,
configuration, the service container, routing, events and PSR-7 responses. Prefer existing
NAF helpers, services and extension interfaces; keep application business rules in the host.
This package declares `type: naf-plugin` and is discovered after installation in a NAF host.
The plugin repository itself is not the application's web root.

Before changing code, read the [shared contribution workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md).
In the multi-repository workspace, the same documents are in the sibling `docs/` checkout;
use the linked copies when working from a standalone clone. Preserve other contributors' work.

Keep the directory contract free of application policy. Keep reusable capability here and application policy in the host. Run composer test and composer validate --strict. Tests are PHPUnit under `tests/Unit`, with the directory and account provider faked in `tests/Fixtures`. Do not contact a live directory or send external messages in tests.

Use PER Coding Style 3.0 and the Nafinity readability rules in `.php-cs-fixer.dist.php`.
Run `composer style:check`; use `composer style:fix` to format source and tests.
Separate validation, preparation, I/O and results with blank lines. Prefer descriptive
local names and named intermediate values to nested expressions; preserve evaluation
order and LDAP cleanup. Document callback signatures without adding mapping abstractions.

User docs: [Signing in against a directory](https://nafphp.github.io/docs/auth-ldap/).
