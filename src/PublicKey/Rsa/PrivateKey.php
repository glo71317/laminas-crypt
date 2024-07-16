<?php

declare(strict_types=1);

namespace Laminas\Crypt\PublicKey\Rsa;

use function file_get_contents;
use function is_readable;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_private_decrypt;
use function openssl_private_encrypt;

use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

/**
 * RSA private key
 */
class PrivateKey extends AbstractKey
{
    /**
     * Public key
     */
    protected ?PublicKey $publicKey = null;

    /**
     * Create private key instance from PEM formatted key file
     *
     * @throws Exception\InvalidArgumentException
     */
    public static function fromFile(string $pemFile, ?string $passPhrase = null): static
    {
        if (! is_readable($pemFile)) {
            throw new Exception\InvalidArgumentException(
                "PEM file '{$pemFile}' is not readable"
            );
        }

        return new static(file_get_contents($pemFile), $passPhrase);
    }

    /**
     * Constructor
     *
     * @throws Exception\RuntimeException
     */
    public function __construct(string $pemString, ?string $passPhrase = null)
    {
        $result = openssl_pkey_get_private($pemString, $passPhrase);
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Unable to load private key; openssl ' . openssl_error_string()
            );
        }

        $this->pemString          = $pemString;
        $this->opensslKeyResource = $result;
        $this->details            = openssl_pkey_get_details($this->opensslKeyResource);
    }

    /**
     * Get the public key
     */
    public function getPublicKey(): PublicKey|null
    {
        if ($this->publicKey === null) {
            $this->publicKey = new PublicKey($this->details['key']);
        }

        return $this->publicKey;
    }

    /**
     * Encrypt using this key
     *
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        if ($data === '' || $data === '0') {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }

        $encrypted = '';
        $result    = openssl_private_encrypt($data, $encrypted, $this->getOpensslKeyResource(), $padding);
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not encrypt; openssl ' . openssl_error_string()
            );
        }

        return $encrypted;
    }

    /**
     * Decrypt using this key
     *
     * Starting in 2.4.9/2.5.2, we changed the default padding to
     * OPENSSL_PKCS1_OAEP_PADDING to prevent Bleichenbacher's chosen-ciphertext
     * attack.
     *
     * @see http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
     *
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function decrypt(string $data, int $padding = OPENSSL_PKCS1_OAEP_PADDING): string
    {
        if (! is_string($data)) {
            throw new Exception\InvalidArgumentException('The data to decrypt must be a string');
        }
        if ('' === $data) {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }

        $decrypted = '';
        $result    = openssl_private_decrypt($data, $decrypted, $this->getOpensslKeyResource(), $padding);
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not decrypt; openssl ' . openssl_error_string()
            );
        }

        return $decrypted;
    }

    public function toString(): string
    {
        return $this->pemString;
    }
}
