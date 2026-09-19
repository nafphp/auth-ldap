<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use Naf\Auth\Ldap\NativeDirectory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What a directory connection accepts before it ever opens one.
 *
 * Construction validates configuration and contacts nothing, so every case here
 * runs without a directory anywhere near it.
 */
final class NativeDirectoryTest extends TestCase
{
    private string $caFile;

    protected function setUp(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'naf-ca-contract-');
        self::assertIsString($file, 'cannot create the temporary CA fixture');
        file_put_contents($file, 'fixture');
        $this->caFile = $file;
    }

    protected function tearDown(): void
    {
        @unlink($this->caFile);
    }

    private function configuration(array $overrides = []): array
    {
        return array_replace([
            'url'          => 'ldaps://directory.example.test',
            'baseDn'       => 'dc=example,dc=test',
            'bindDn'       => 'cn=service',
            'bindPassword' => 'fixture',
            'caFile'       => $this->caFile,
        ], $overrides);
    }

    public static function acceptedConfigurations(): array
    {
        return [
            'ldaps'                => [[]],
            'ldap with trailing /' => [['url' => 'ldap://directory.example.test/']],
            'shortest timeout'     => [['timeout' => 1]],
            'longest timeout'      => [['timeout' => 30]],
        ];
    }

    #[DataProvider('acceptedConfigurations')]
    public function testAValidConfigurationIsAcceptedWithoutConnecting(array $overrides): void
    {
        $directory = new NativeDirectory(...$this->configuration($overrides));

        self::assertInstanceOf(NativeDirectory::class, $directory);
    }

    public static function rejectedConfigurations(): array
    {
        return [
            'unsupported scheme'   => [['url' => 'http://directory']],
            'missing host'         => [['url' => 'ldap:///']],
            'embedded credentials' => [['url' => 'ldap://user:secret@directory']],
            'embedded base DN'     => [['url' => 'ldaps://directory/dc=example']],
            'query string'         => [['url' => 'ldaps://directory?filter=uid']],
            'fragment'             => [['url' => 'ldaps://directory#fragment']],
            'empty base DN'        => [['baseDn' => '']],
            'anonymous bind'       => [['bindDn' => '']],
            'empty bind password'  => [['bindPassword' => '']],
            'invalid username'     => [['usernameAttribute' => 'uid)(objectClass=*']],
            'invalid subject'      => [['subjectAttribute' => 'entryUUID)']],
            'timeout too short'    => [['timeout' => 0]],
            'timeout too long'     => [['timeout' => 31]],
            'empty filter'         => [['allowedFilter' => '']],
            'missing filter start' => [['allowedFilter' => 'objectClass=inetOrgPerson)']],
            'missing filter end'   => [['allowedFilter' => '(objectClass=inetOrgPerson']],
        ];
    }

    #[DataProvider('rejectedConfigurations')]
    public function testAnUnsafeConfigurationIsRefused(array $overrides): void
    {
        $this->expectException(InvalidArgumentException::class);

        new NativeDirectory(...$this->configuration($overrides));
    }

    public function testACaFileThatIsNotThereIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new NativeDirectory(...$this->configuration(['caFile' => $this->caFile . '.missing']));
    }
}
