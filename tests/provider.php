<?php

declare(strict_types=1);

use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Credentials\PasswordCredentials;
use Naf\Auth\Identity\Identity;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Ldap\DirectoryInterface;
use Naf\Auth\Ldap\LdapProvider;
use Naf\Auth\Provider\ProviderInterface;

$directory = new class implements DirectoryInterface {
    public bool $active               = true;
    public int $authenticationCalls   = 0;
    public ?RuntimeException $failure = null;

    public function authenticate(string $username, string $password): ?string
    {
        $this->authenticationCalls++;

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $username === 'alice' && $password === 'test-password' ? 'immutable-uuid' : null;
    }

    public function hasSubject(string $subject): bool
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->active && $subject === 'immutable-uuid';
    }
};

$accounts = new class implements ProviderInterface {
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
};

$provider = new LdapProvider(
    $directory,
    fn(string $subject): ?string => $subject === 'immutable-uuid' ? '42' : null,
    fn(string $identifier): ?string => $identifier === '42' ? 'immutable-uuid' : null,
    $accounts,
);

// Unsupported and empty credentials must never reach the directory.
$invalidCredentials = [
    new class implements CredentialsInterface {},
    new PasswordCredentials('', 'test-password'),
    new PasswordCredentials('alice', ''),
];

foreach ($invalidCredentials as $credentials) {
    check($provider->authenticate($credentials) === null, 'Unsupported or empty credentials accepted.');
}

check($directory->authenticationCalls === 0, 'Invalid credentials reached the directory.');
check($accounts->lookups === 0, 'Invalid credentials reached the account provider.');

check(
    $provider->authenticate(new PasswordCredentials('alice', 'wrong')) === null,
    'Invalid directory password accepted.',
);
check($accounts->lookups === 0, 'A failed directory login looked up a local account.');

$credentials = new PasswordCredentials('alice', 'test-password');

check($provider->authenticate($credentials)?->getIdentifier() === '42', 'Linked account not authenticated.');
check($provider->find('42')?->getIdentifier() === '42', 'Linked account not restored.');
check($provider->find('99') === null, 'Unlinked account restored.');

// Both directions require an explicit, valid mapping before loading an account.
foreach ([null, '', 42, []] as $invalidMapping) {
    $unlinkedProvider = new LdapProvider(
        $directory,
        fn() => $invalidMapping,
        fn() => $invalidMapping,
        $accounts,
    );
    $previousLookups = $accounts->lookups;

    check($unlinkedProvider->authenticate($credentials) === null, 'Invalid account mapping accepted.');
    check($unlinkedProvider->find('42') === null, 'Invalid subject mapping accepted.');
    check($accounts->lookups === $previousLookups, 'Invalid mapping reached the account provider.');
}

$accounts->exists = false;

check($provider->authenticate($credentials) === null, 'Deleted account authenticated.');
check($provider->find('42') === null, 'Deleted account restored.');

$accounts->exists  = true;
$directory->active = false;
$previousLookups   = $accounts->lookups;

check($provider->find('42') === null, 'Directory revocation ignored.');
check($accounts->lookups === $previousLookups, 'Revoked directory subject reached the account provider.');

// Directory outages must propagate, without falling back to local credentials.
$directory->failure = new RuntimeException('Directory unavailable.');
$previousLookups    = $accounts->lookups;
$operations         = [
    fn() => $provider->authenticate($credentials),
    fn() => $provider->find('42'),
];

foreach ($operations as $operation) {
    try {
        $operation();
        throw new LogicException('Directory failure was swallowed.');
    } catch (RuntimeException $exception) {
        check($exception === $directory->failure, 'Directory failure was replaced.');
    }
}

check($accounts->lookups === $previousLookups, 'Directory failure reached the account provider.');
