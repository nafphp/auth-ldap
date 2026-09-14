<?php

declare(strict_types=1);

namespace Naf\Auth\Ldap;

use Closure;
use Naf\Auth\Credentials\{CredentialsInterface,PasswordCredentials};
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;

/** The host owns explicit subject-to-account links. There is no e-mail matching or auto-provisioning. */
final class LdapProvider implements ProviderInterface
{
    public function __construct(private DirectoryInterface $directory, private Closure $accountForSubject, private Closure $subjectForAccount, private ProviderInterface $accounts)
    {
    }
    public function authenticate(#[\SensitiveParameter] CredentialsInterface $credentials): ?IdentityInterface
    {
        if (!$credentials instanceof PasswordCredentials || $credentials->username === '' || $credentials->password === '') {
            return null;
        }
        $subject = $this->directory->authenticate($credentials->username, $credentials->password);
        if ($subject === null) {
            return null;
        }$id = ($this->accountForSubject)($subject);
        return is_string($id) && $id !== '' ? $this->accounts->find($id) : null;
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
