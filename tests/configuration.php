<?php

declare(strict_types=1);

use Naf\Auth\Ldap\NativeDirectory;

$caFile = tempnam(sys_get_temp_dir(), 'naf-ca-contract-');
check($caFile !== false, 'Cannot create the temporary CA fixture.');

try {
    check(file_put_contents($caFile, 'fixture') !== false, 'Cannot write the CA fixture.');

    $configuration = [
        'url'          => 'ldaps://directory.example.test',
        'baseDn'       => 'dc=example,dc=test',
        'bindDn'       => 'cn=service',
        'bindPassword' => 'fixture',
        'caFile'       => $caFile,
    ];

    // Construction validates configuration only; it must not open a connection.
    new NativeDirectory(...$configuration);
    new NativeDirectory(...array_replace($configuration, ['url' => 'ldap://directory.example.test/']));
    new NativeDirectory(...array_replace($configuration, ['timeout' => 1]));
    new NativeDirectory(...array_replace($configuration, ['timeout' => 30]));

    $invalidConfigurations = [
        'unsupported scheme'   => ['url' => 'http://directory'],
        'missing host'         => ['url' => 'ldap:///'],
        'embedded credentials' => ['url' => 'ldap://user:secret@directory'],
        'embedded base DN'     => ['url' => 'ldaps://directory/dc=example'],
        'query string'         => ['url' => 'ldaps://directory?filter=uid'],
        'fragment'             => ['url' => 'ldaps://directory#fragment'],
        'empty base DN'        => ['baseDn' => ''],
        'anonymous bind'       => ['bindDn' => ''],
        'empty bind password'  => ['bindPassword' => ''],
        'missing CA file'      => ['caFile' => $caFile . '.missing'],
        'invalid username'     => ['usernameAttribute' => 'uid)(objectClass=*'],
        'invalid subject'      => ['subjectAttribute' => 'entryUUID)'],
        'timeout too short'    => ['timeout' => 0],
        'timeout too long'     => ['timeout' => 31],
        'empty filter'         => ['allowedFilter' => ''],
        'missing filter start' => ['allowedFilter' => 'objectClass=inetOrgPerson)'],
        'missing filter end'   => ['allowedFilter' => '(objectClass=inetOrgPerson'],
    ];

    foreach ($invalidConfigurations as $description => $override) {
        try {
            new NativeDirectory(...array_replace($configuration, $override));
            throw new RuntimeException('Unsafe LDAP configuration accepted: ' . $description);
        } catch (InvalidArgumentException) {
            // Rejection is the expected result for each invalid configuration.
        }
    }
} finally {
    unlink($caFile);
}
