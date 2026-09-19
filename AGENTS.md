# Working on auth-ldap

Follow ../AGENTS.md and ../docs/AGENT_WORKFLOW.md. Keep the directory contract free of application policy. Keep reusable capability here and application policy in the host. Run composer test and composer validate --strict. Tests are PHPUnit under `tests/Unit`, with the directory and account provider faked in `tests/Fixtures`. Do not contact a live directory or send external messages in tests.

Use PER Coding Style 3.0 and the Nafinity readability rules in `.php-cs-fixer.dist.php`.
Run `composer style:check`; use `composer style:fix` to format source and tests.
Separate validation, preparation, I/O and results with blank lines. Prefer descriptive
local names and named intermediate values to nested expressions; preserve evaluation
order and LDAP cleanup. Document callback signatures without adding mapping abstractions.
