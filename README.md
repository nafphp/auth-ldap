# naf/auth-ldap (unreleased, opt-in)

`LdapProvider` implements the existing NAF `ProviderInterface`. Bind it lazily and register a named auth provider. `DirectoryInterface` verifies credentials and checks an immutable subject. The host supplies two closures for explicit subject/account mapping and its existing account provider. No identity is created or linked by email. NAF Auth still enforces `isActive` and rotates its session.

`NativeDirectory` requires LDAPS or mandatory StartTLS, a trusted CA, non-anonymous search credentials, a base DN, an immutable subject attribute (default `entryUUID`), and an allowed-account filter. For Active Directory configure the account attribute, stable subject representation and disabled-account filter for your actual directory before activation; the initial adapter targets textual subjects such as OpenLDAP entryUUID. LDAP syntax is escaped with `LDAP_ESCAPE_FILTER`; referrals are disabled, ambiguous searches refused, and network/search timeouts bounded. Session restoration rechecks the linked subject; directory failures fail closed.

TLS options are configured before creating the connection, as required by the [PHP LDAP documentation](https://www.php.net/manual/en/function.ldap-set-option.php). PHP/OpenLDAP TLS options are process-global; use one trust configuration per process. The plugin cannot determine a directory's disabled-account semantics: include those in `allowedFilter`.

Contract tests cover the provider using a fake directory. A real trusted TLS directory must be tested before enabling it for a deployment. Do not advertise fixture tests as a live LDAP verification.

## Account mapping

The host supplies `accountForSubject(string $subject): ?string` and
`subjectForAccount(string $identifier): ?string`. Return the explicitly linked identifier
or `null` when no link exists. `LdapProvider` verifies the directory credentials before
looking up the local account; session restoration checks the directory subject again.
Local account lookup stays with the supplied `ProviderInterface`.

## Development

Use PHP 8.3+ with `ext-ldap` and Composer in this directory:

```sh
composer install
composer test
composer style:check
composer validate --strict
```

`composer style:fix` applies [PER Coding Style 3.0](https://github.com/php-fig/per-coding-style/blob/3.0.0/spec.md),
the successor to PSR-12, with the readability rules used in Nafinity. The pinned formatter
is a development dependency; applications installing this plugin do not install it.
Prefer PHP 8.3 when running the formatter to match the minimum supported runtime.

Use descriptive local names, separate validation, setup, I/O and result handling with blank
lines, and align `=` / `=>` only within related groups. Keep the existing directory and
provider contracts; simple operations do not need additional services or wrappers.

`tests/provider.php` covers linked, missing and revoked accounts, rejected credentials,
mapping failures and directory outages. `tests/configuration.php` checks configuration
boundaries without connecting to LDAP. `NAF_TEST_AUTOLOAD=/path/to/vendor/autoload.php composer test`
also runs the contracts against a host that has this checkout installed.
