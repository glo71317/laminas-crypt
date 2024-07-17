<?php

declare(strict_types=1);

namespace Laminas\Crypt\Password;

use Laminas\Crypt\Hash;

/**
 * Bcrypt algorithm using crypt() function of PHP with password
 * hashed using SHA2 to allow for passwords >72 characters.
 */
class BcryptSha extends Bcrypt
{
    /**
     * BcryptSha
     *
     * @throws Exception\RuntimeException
     */
    public function create(string $password): string
    {
        return parent::create(Hash::compute('sha256', $password));
    }

    /**
     * Verify if a password is correct against a hash value
     *
     * @throws Exception\RuntimeException When the hash is unable to be processed.
     */
    public function verify(string $password, string $hash): bool
    {
        return parent::verify(Hash::compute('sha256', $password), $hash);
    }
}
