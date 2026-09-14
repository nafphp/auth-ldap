<?php

declare(strict_types=1);

namespace Naf\Auth\Ldap;

use InvalidArgumentException;
use LDAP\Connection;
use RuntimeException;
use SensitiveParameter;
use Throwable;

final class NativeDirectory implements DirectoryInterface
{
    public function __construct(
        private string $url,
        private string $baseDn,
        private string $bindDn,
        #[SensitiveParameter]
        private string $bindPassword,
        private string $caFile,
        private string $usernameAttribute = 'uid',
        private string $subjectAttribute = 'entryUUID',
        private string $allowedFilter = '(objectClass=inetOrgPerson)',
        private int $timeout = 5,
    ) {
        $parts = parse_url($url);
        if (
            !$parts
            || !in_array($parts['scheme'] ?? '', ['ldap', 'ldaps'], true)
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
        ) {
            throw new InvalidArgumentException('Use one explicit ldap:// or ldaps:// server URL.');
        }
        if ($baseDn === '' || $bindDn === '' || $bindPassword === '') {
            throw new InvalidArgumentException(
                'LDAP requires a search base and non-anonymous service credentials.',
            );
        }
        if (!is_file($caFile) || !is_readable($caFile)) {
            throw new InvalidArgumentException('A readable trusted LDAP CA file is required.');
        }
        foreach ([$usernameAttribute, $subjectAttribute] as $attribute) {
            if (!preg_match('/^[a-zA-Z][a-zA-Z0-9-]*$/D', $attribute)) {
                throw new InvalidArgumentException('Invalid LDAP attribute.');
            }
        }
        if ($timeout < 1 || $timeout > 30) {
            throw new InvalidArgumentException('LDAP timeout must be 1–30 seconds.');
        }
        if (!str_starts_with($allowedFilter, '(') || !str_ends_with($allowedFilter, ')')) {
            throw new InvalidArgumentException('Configure an explicit allowed-account filter.');
        }
    }

    public function authenticate(string $username, #[SensitiveParameter] string $password): ?string
    {
        if (
            $username === ''
            || $password === ''
            || strlen($username) > 254
            || strlen($password) > 1024
        ) {
            return null;
        }
        $connection = $this->connect();

        try {
            $entry = $this->search($connection, $this->usernameAttribute, $username);
            if (!$entry) {
                return null;
            }
            if (!@ldap_bind($connection, $entry['dn'], $password)) {
                return null;
            }
            $subject = $entry[strtolower($this->subjectAttribute)][0] ?? null;

            return is_string($subject) && $subject !== '' ? $subject : null;
        } finally {
            ldap_unbind($connection);
        }
    }

    public function hasSubject(string $subject): bool
    {
        if ($subject === '' || strlen($subject) > 190) {
            return false;
        }
        $connection = $this->connect();

        try {
            return $this->search($connection, $this->subjectAttribute, $subject) !== null;
        } finally {
            ldap_unbind($connection);
        }
    }

    private function connect(): Connection
    {
        // PHP/OpenLDAP initializes TLS context globally. Never weaken certificate verification.
        foreach (
            [
                LDAP_OPT_X_TLS_REQUIRE_CERT => LDAP_OPT_X_TLS_DEMAND,
                LDAP_OPT_X_TLS_CACERTFILE   => $this->caFile,
            ] as $option => $value
        ) {
            if (!ldap_set_option(null, $option, $value)) {
                throw new RuntimeException('Cannot configure LDAP TLS.');
            }
        }
        $connection = ldap_connect($this->url);
        if (!$connection) {
            throw new RuntimeException('Cannot initialize LDAP.');
        }

        try {
            foreach (
                [
                    LDAP_OPT_PROTOCOL_VERSION => 3,
                    LDAP_OPT_REFERRALS        => 0,
                    LDAP_OPT_NETWORK_TIMEOUT  => $this->timeout,
                    LDAP_OPT_TIMELIMIT        => $this->timeout,
                ] as $option => $value
            ) {
                if (!ldap_set_option($connection, $option, $value)) {
                    throw new RuntimeException('Cannot configure LDAP connection.');
                }
            }
            if (str_starts_with($this->url, 'ldap://') && !@ldap_start_tls($connection)) {
                throw new RuntimeException('LDAP TLS negotiation failed.');
            }
            if (!@ldap_bind($connection, $this->bindDn, $this->bindPassword)) {
                throw new RuntimeException('LDAP service authentication failed.');
            }

            return $connection;
        } catch (Throwable $e) {
            ldap_unbind($connection);
            throw $e;
        }
    }

    private function search(Connection $connection, string $attribute, string $value): ?array
    {
        $filter = '(&'
            . $this->allowedFilter
            . '('
            . $attribute
            . '='
            . ldap_escape($value, '', LDAP_ESCAPE_FILTER)
            . '))';
        $result = @ldap_search(
            $connection,
            $this->baseDn,
            $filter,
            [$this->subjectAttribute],
            0,
            2,
            $this->timeout,
        );
        if (!$result) {
            throw new RuntimeException('LDAP search failed.');
        }

        try {
            $entries = ldap_get_entries($connection, $result);

            return is_array($entries) && ($entries['count'] ?? 0) === 1 ? $entries[0] : null;
        } finally {
            ldap_free_result($result);
        }
    }
}
