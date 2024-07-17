<?php

declare(strict_types=1);

namespace Laminas\Crypt\PublicKey;

use Laminas\Crypt\PublicKey\Rsa\Exception;
use Laminas\Stdlib\AbstractOptions;

use function array_replace;
use function constant;
use function defined;
use function openssl_error_string;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function strtolower;
use function strtoupper;

use const OPENSSL_KEYTYPE_RSA;

/**
 * RSA instance options
 */
class RsaOptions extends AbstractOptions
{
    protected ?Rsa\PrivateKey $privateKey = null;

    protected ?Rsa\PublicKey $publicKey = null;

    protected string $hashAlgorithm = 'sha1';

    /**
     * Signature hash algorithm defined by openss constants
     */
    protected ?int $opensslSignatureAlgorithm = null;

    protected ?string $passPhrase = null;

    /**
     * Output is binary
     */
    protected bool $binaryOutput = true;

    /**
     * OPENSSL padding
     */
    protected ?int $opensslPadding = null;

    /**
     * Set private key
     */
    public function setPrivateKey(Rsa\PrivateKey $key): static
    {
        $this->privateKey = $key;
        $this->publicKey  = $this->privateKey->getPublicKey();
        return $this;
    }

    /**
     * Get private key
     */
    public function getPrivateKey(): Rsa\PrivateKey|null
    {
        return $this->privateKey;
    }

    /**
     * Set public key
     */
    public function setPublicKey(Rsa\PublicKey $key): static
    {
        $this->publicKey = $key;
        return $this;
    }

    /**
     * Get public key
     */
    public function getPublicKey(): Rsa\PublicKey|null
    {
        return $this->publicKey;
    }

    /**
     * Set pass phrase
     */
    public function setPassPhrase(string $phrase): static
    {
        $this->passPhrase = $phrase;
        return $this;
    }

    /**
     * Get pass phrase
     *
     * @return string
     */
    public function getPassPhrase(): string|null
    {
        return $this->passPhrase;
    }

    /**
     * Set hash algorithm
     *
     * @throws Rsa\Exception\RuntimeException
     * @throws Rsa\Exception\InvalidArgumentException
     */
    public function setHashAlgorithm(string $hash): static
    {
        $hashUpper = strtoupper($hash);
        if (! defined('OPENSSL_ALGO_' . $hashUpper)) {
            throw new Exception\InvalidArgumentException(
                "Hash algorithm '{$hash}' is not supported"
            );
        }

        $this->hashAlgorithm             = strtolower($hash);
        $this->opensslSignatureAlgorithm = constant('OPENSSL_ALGO_' . $hashUpper);
        return $this;
    }

    /**
     * Get hash algorithm
     */
    public function getHashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    public function getOpensslSignatureAlgorithm(): int
    {
        if ($this->opensslSignatureAlgorithm === null) {
            $this->opensslSignatureAlgorithm = constant('OPENSSL_ALGO_' . strtoupper($this->hashAlgorithm));
        }
        return $this->opensslSignatureAlgorithm;
    }

    /**
     * Enable/disable the binary output
     */
    public function setBinaryOutput(bool $value): static
    {
        $this->binaryOutput = $value;
        return $this;
    }

    /**
     * Get the value of binary output
     */
    public function getBinaryOutput(): bool
    {
        return $this->binaryOutput;
    }

    /**
     * Get the OPENSSL padding
     */
    public function getOpensslPadding(): int|null
    {
        return $this->opensslPadding;
    }

    /**
     * Set the OPENSSL padding
     */
    public function setOpensslPadding(int $opensslPadding): static
    {
        $this->opensslPadding = $opensslPadding;
        return $this;
    }

    /**
     * Generate new private/public key pair
     *
     * @throws Rsa\Exception\RuntimeException
     */
    public function generateKeys(array $opensslConfig = []): static
    {
        $opensslConfig = array_replace(
            [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => Rsa\PrivateKey::DEFAULT_KEY_SIZE,
                'digest_alg'       => $this->getHashAlgorithm(),
            ],
            $opensslConfig
        );

        // generate
        $resource = openssl_pkey_new($opensslConfig);
        if (false === $resource) {
            throw new Exception\RuntimeException(
                'Can not generate keys; openssl ' . openssl_error_string()
            );
        }

        // export key
        $passPhrase = $this->getPassPhrase();
        $result     = openssl_pkey_export($resource, $private, $passPhrase, $opensslConfig);
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not export key; openssl ' . openssl_error_string()
            );
        }

        $details          = openssl_pkey_get_details($resource);
        $this->privateKey = new Rsa\PrivateKey($private, $passPhrase);
        $this->publicKey  = new Rsa\PublicKey($details['key']);

        return $this;
    }
}
