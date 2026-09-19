# NAF Auth LDAP

> **Sign in against an LDAP directory, without giving up the local account.**

`LdapProvider` implements NAF's existing `ProviderInterface`, so a directory becomes one more
named auth provider. The directory verifies the credentials; the host decides which local
account a directory subject belongs to, through two explicit mapping closures. No identity is
ever created or linked by email address.

> 🧩 Part of the official NAF plugin collection.
> Install it when people sign in against a directory, and nothing else.

## Documentation

**[Read the documentation →](https://nafphp.github.io/docs/)**

What this package does, how the directory is configured and what it requires lives in the
[NAF documentation](https://nafphp.github.io/docs/). Not sure which packages you need?
[Start here](https://nafphp.github.io/docs/choosing-packages/).

## Install

```bash
composer require naf/auth-ldap
```

Needs `ext-ldap`.

## License

MIT. Part of [NAF](https://github.com/nafphp/framework).
