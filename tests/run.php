<?php

declare(strict_types=1);
require getenv('NAF_TEST_AUTOLOAD') ?: dirname(__DIR__).'/vendor/autoload.php';
function check(bool $value, string $message): void
{
    if (!$value) {
        throw new RuntimeException($message);
    }
}

use Naf\Auth\Ldap\{LdapProvider,DirectoryInterface,NativeDirectory};
use Naf\Auth\Provider\ProviderInterface;
use Naf\Auth\Identity\{Identity,IdentityInterface};
use Naf\Auth\Credentials\{CredentialsInterface,PasswordCredentials};

$directory = new class () implements DirectoryInterface {
    public bool $active = true;
    public int $calls = 0;
    public function authenticate(string $username, string $password): ?string
    {
        $this->calls++;
        return $username === 'alice' && $password === 'test-password' ? 'immutable-uuid' : null;
    }public function hasSubject(string $subject): bool
    {
        return $this->active && $subject === 'immutable-uuid';
    }
};
$accounts = new class () implements ProviderInterface {
    public function authenticate(CredentialsInterface $credentials): ?IdentityInterface
    {
        return null;
    }public function find(string $identifier): ?IdentityInterface
    {
        return $identifier === '42' ? new Identity('42') : null;
    }
};
$provider = new LdapProvider($directory, fn ($subject) => $subject === 'immutable-uuid' ? '42' : null, fn ($id) => $id === '42' ? 'immutable-uuid' : null, $accounts);
check($provider->authenticate(new PasswordCredentials('alice', '')) === null && $directory->calls === 0, 'anonymous bind risk');
check($provider->authenticate(new PasswordCredentials('alice', 'wrong')) === null, 'invalid password');
check($provider->authenticate(new PasswordCredentials('alice', 'test-password'))?->getIdentifier() === '42', 'linked account');
check($provider->find('99') === null, 'unlinked account');
$directory->active = false;
check($provider->find('42') === null, 'directory revocation ignored');
$ca = tempnam(sys_get_temp_dir(), 'naf-ca-contract-');
file_put_contents($ca, 'fixture');
try {
    foreach ([['url' => 'http://directory'],['url' => 'ldap://user:secret@directory'],['usernameAttribute' => 'uid)(objectClass=*'],['timeout' => 0],['bindPassword' => '']] as $override) {
        $args = array_replace(['url' => 'ldaps://directory.example.test','baseDn' => 'dc=example,dc=test','bindDn' => 'cn=service','bindPassword' => 'fixture','caFile' => $ca], $override);
        try {
            new NativeDirectory(...$args);
            throw new RuntimeException('Unsafe configuration accepted');
        } catch (InvalidArgumentException) {
        }
    }
} finally {
    unlink($ca);
}
echo "LDAP provider and configuration contract cases passed; no live directory contacted.\n";
