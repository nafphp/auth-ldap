# naf/auth-ldap (unreleased, opt-in)

`LdapProvider` implements the existing NAF `ProviderInterface`. Bind it lazily and register a named auth provider. `DirectoryInterface` verifies credentials and checks an immutable subject. The host supplies two closures for explicit subject/account mapping and its existing account provider. No identity is created or linked by email. NAF Auth still enforces `isActive` and rotates its session.

`NativeDirectory` requires LDAPS or mandatory StartTLS, a trusted CA, non-anonymous search credentials, a base DN, an immutable subject attribute (default `entryUUID`), and an allowed-account filter. For Active Directory configure the account attribute, stable subject representation and disabled-account filter for your actual directory before activation; the initial adapter targets textual subjects such as OpenLDAP entryUUID. LDAP syntax is escaped with `LDAP_ESCAPE_FILTER`; referrals are disabled, ambiguous searches refused, and network/search timeouts bounded. Session restoration rechecks the linked subject; directory failures fail closed.

TLS options are configured before creating the connection, as required by the [PHP LDAP documentation](https://www.php.net/manual/en/function.ldap-set-option.php). PHP/OpenLDAP TLS options are process-global; use one trust configuration per process. The plugin cannot determine a directory's disabled-account semantics: include those in `allowedFilter`.

Contract tests cover the provider using a fake directory. A real trusted TLS directory must be tested before enabling it for a deployment. Do not advertise fixture tests as a live LDAP verification.
