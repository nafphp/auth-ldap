<?php

declare(strict_types=1);

namespace Naf\Auth\Ldap;

use Closure;
use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Credentials\PasswordCredentials;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;
use SensitiveParameter;

/**
 * Authenticate explicitly linked accounts; the host owns subject-to-account mapping.
 */
final class LdapProvider implements ProviderInterface
{
    /**
     * @param Closure(string): ?string $accountForSubject Maps a directory subject to an account identifier.
     * @param Closure(string): ?string $subjectForAccount Maps an account identifier to a directory subject.
     */
    public function __construct(
        private DirectoryInterface $directory,
        private Closure $accountForSubject,
        private Closure $subjectForAccount,
        private ProviderInterface $accounts,
    ) {
    }

    public function authenticate(
        #[SensitiveParameter]
        CredentialsInterface $credentials,
    ): ?IdentityInterface {
        if (
            !($credentials instanceof PasswordCredentials)
            || $credentials->username === ''
            || $credentials->password === ''
        ) {
            return null;
        }

        $subject = $this->directory->authenticate($credentials->username, $credentials->password);
        if ($subject === null) {
            return null;
        }

        $accountIdentifier = ($this->accountForSubject)($subject);
        if (!is_string($accountIdentifier) || $accountIdentifier === '') {
            return null;
        }

        return $this->accounts->find($accountIdentifier);
    }

    public function find(string $identifier): ?IdentityInterface
    {
        $subject = ($this->subjectForAccount)($identifier);
        if (!is_string($subject) || !$this->directory->hasSubject($subject)) {
            return null;
        }

        return $this->accounts->find($identifier);
    }
}
