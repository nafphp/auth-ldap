<?php

declare(strict_types=1);

namespace Naf\Auth\Ldap;

use SensitiveParameter;

interface DirectoryInterface
{
    /** Return an immutable directory subject after credential verification, otherwise null. */
    public function authenticate(
        string $username,
        #[SensitiveParameter]
        string $password,
    ): ?string;

    public function hasSubject(string $subject): bool;
}
