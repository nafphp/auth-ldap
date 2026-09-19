<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use LogicException;
use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Identity\Identity;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;

/**
 * The local account source the LDAP provider defers to.
 *
 * Its authenticate() throws on purpose: a directory password must never be
 * forwarded to local credentials, and a test that does so should fail loudly
 * rather than quietly pass.
 */
final class AccountProvider implements ProviderInterface
{
    public bool $exists = true;
    public int $lookups = 0;

    public function authenticate(CredentialsInterface $credentials): ?IdentityInterface
    {
        throw new LogicException('LDAP passwords must not be forwarded to the account provider.');
    }

    public function find(string $identifier): ?IdentityInterface
    {
        $this->lookups++;

        return $this->exists && $identifier === '42' ? new Identity('42') : null;
    }
}
