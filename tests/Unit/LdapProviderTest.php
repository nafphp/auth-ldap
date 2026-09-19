<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Credentials\PasswordCredentials;
use Naf\Auth\Ldap\LdapProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Fixtures\AccountProvider;
use Tests\Fixtures\FakeDirectory;

/** Signing in against a directory, and the local account it is allowed to reach. */
final class LdapProviderTest extends TestCase
{
    private FakeDirectory $directory;
    private AccountProvider $accounts;
    private LdapProvider $provider;

    protected function setUp(): void
    {
        $this->directory = new FakeDirectory();
        $this->accounts  = new AccountProvider();
        $this->provider  = new LdapProvider(
            $this->directory,
            static fn(string $subject): ?string => $subject === 'immutable-uuid' ? '42' : null,
            static fn(string $identifier): ?string => $identifier === '42' ? 'immutable-uuid' : null,
            $this->accounts,
        );
    }

    public static function unusableCredentials(): array
    {
        return [
            'unsupported type' => [new class implements CredentialsInterface {}],
            'no username'      => [new PasswordCredentials('', 'test-password')],
            'no password'      => [new PasswordCredentials('alice', '')],
        ];
    }

    #[DataProvider('unusableCredentials')]
    public function testCredentialsItCannotUseNeverReachTheDirectory(CredentialsInterface $credentials): void
    {
        self::assertNull($this->provider->authenticate($credentials));
        self::assertSame(0, $this->directory->authenticationCalls, 'the directory was contacted');
        self::assertSame(0, $this->accounts->lookups, 'a local account was looked up');
    }

    public function testAWrongDirectoryPasswordNeverLooksUpALocalAccount(): void
    {
        self::assertNull($this->provider->authenticate(new PasswordCredentials('alice', 'wrong')));
        self::assertSame(1, $this->directory->authenticationCalls);
        self::assertSame(0, $this->accounts->lookups, 'a failed directory login reached the account provider');
    }

    public function testALinkedAccountIsAuthenticatedAndRestored(): void
    {
        $identity = $this->provider->authenticate(new PasswordCredentials('alice', 'test-password'));

        self::assertSame('42', $identity?->getIdentifier());
        self::assertSame('42', $this->provider->find('42')?->getIdentifier());
        self::assertNull($this->provider->find('99'), 'an unlinked identifier was restored');
    }

    public static function unusableMappings(): array
    {
        return [
            'null'         => [null],
            'empty string' => [''],
            'integer'      => [42],
            'empty array'  => [[]],
        ];
    }

    #[DataProvider('unusableMappings')]
    public function testBothDirectionsNeedAnExplicitValidMapping(mixed $mapping): void
    {
        $unlinked = new LdapProvider(
            $this->directory,
            static fn() => $mapping,
            static fn() => $mapping,
            $this->accounts,
        );

        self::assertNull($unlinked->authenticate(new PasswordCredentials('alice', 'test-password')));
        self::assertNull($unlinked->find('42'));
        self::assertSame(0, $this->accounts->lookups, 'an invalid mapping reached the account provider');
    }

    public function testADeletedLocalAccountCannotSignInWithAValidDirectoryLogin(): void
    {
        $this->accounts->exists = false;

        self::assertNull($this->provider->authenticate(new PasswordCredentials('alice', 'test-password')));
        self::assertNull($this->provider->find('42'));
    }

    public function testASubjectTheDirectoryNoLongerKnowsIsNotRestored(): void
    {
        $this->directory->active = false;

        self::assertNull($this->provider->find('42'), 'a revoked directory subject was restored');
        self::assertSame(0, $this->accounts->lookups, 'a revoked subject reached the account provider');
    }

    public function testADirectoryOutageIsRaisedRatherThanFallingBackToLocalCredentials(): void
    {
        $this->directory->failure = new RuntimeException('Directory unavailable.');

        foreach ([
            fn() => $this->provider->authenticate(new PasswordCredentials('alice', 'test-password')),
            fn() => $this->provider->find('42'),
        ] as $operation) {
            try {
                $operation();
                self::fail('the directory failure was swallowed');
            } catch (RuntimeException $exception) {
                self::assertSame($this->directory->failure, $exception, 'the failure was replaced');
            }
        }

        self::assertSame(0, $this->accounts->lookups, 'an outage reached the account provider');
    }
}
