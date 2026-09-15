<?php

declare(strict_types=1);

require getenv('NAF_TEST_AUTOLOAD') ?: dirname(__DIR__) . '/vendor/autoload.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

require __DIR__ . '/provider.php';
require __DIR__ . '/configuration.php';

echo "LDAP provider and configuration contract cases passed; no live directory contacted.\n";
