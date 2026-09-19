<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Naf\Auth\Ldap\DirectoryInterface;
use RuntimeException;

/**
 * A directory that answers from memory.
 *
 * It counts the calls it receives, so a test can assert that credentials the
 * provider should have rejected never reached a directory at all.
 */
final class FakeDirectory implements DirectoryInterface
{
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
}
