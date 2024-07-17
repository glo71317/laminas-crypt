<?php

declare(strict_types=1);

namespace Laminas\Crypt\PublicKey;

use Laminas\Crypt\PublicKey\Rsa\AbstractKey;
use Laminas\Crypt\PublicKey\Rsa\Exception;
use Laminas\Crypt\PublicKey\Rsa\PrivateKey;
use Laminas\Crypt\PublicKey\Rsa\PublicKey;
use Laminas\Crypt\PublicKey\RsaOptions;
use Laminas\Stdlib\ArrayUtils;
use Traversable;

use function base64_decode;
use function base64_encode;
use function extension_loaded;
use function is_array;
use function is_file;
use function is_string;
use function openssl_error_string;
use function openssl_sign;
use function openssl_verify;
use function trim;

/**
 * Implementation of the RSA public key encryption algorithm.
 */
class Rsa
{
    public const MODE_AUTO   = 1;
    public const MODE_BASE64 = 2;
    public const MODE_RAW    = 3;

    /**
     * RSA instance factory
     *
     * @throws Rsa\Exception\RuntimeException
     * @throws Rsa\Exception\InvalidArgumentException
     */
    public static function factory(Traversable|array $options): Rsa
    {
        if (! extension_loaded('openssl')) {
            throw new Exception\RuntimeException(
                'Can not create Laminas\Crypt\PublicKey\Rsa; openssl extension needs to be loaded'
            );
        }

        if ($options instanceof Traversable) {
            $options = ArrayUtils::iteratorToArray($options);
        } elseif (! is_array($options)) {
            throw new Exception\InvalidArgumentException(
                'The options parameter must be an array or a Traversable'
            );
        }

        $privateKey = null;
        $passPhrase = $options['pass_phrase'] ?? null;
        if (isset($options['private_key'])) {
            if (is_file($options['private_key'])) {
                $privateKey = PrivateKey::fromFile($options['private_key'], $passPhrase);
            } elseif (is_string($options['private_key'])) {
                $privateKey = new PrivateKey($options['private_key'], $passPhrase);
            } else {
                throw new Exception\InvalidArgumentException(
                    'Parameter "private_key" must be PEM formatted string or path to key file'
                );
            }
            unset($options['private_key']);
        }

        $publicKey = null;
        if (isset($options['public_key'])) {
            if (is_file($options['public_key'])) {
                $publicKey = PublicKey::fromFile($options['public_key']);
            } elseif (is_string($options['public_key'])) {
                $publicKey = new PublicKey($options['public_key']);
            } else {
                throw new Exception\InvalidArgumentException(
                    'Parameter "public_key" must be PEM/certificate string or path to key/certificate file'
                );
            }
            unset($options['public_key']);
        }

        $options = new RsaOptions($options);
        if ($privateKey instanceof Rsa\PrivateKey) {
            $options->setPrivateKey($privateKey);
        }
        if ($publicKey instanceof Rsa\PublicKey) {
            $options->setPublicKey($publicKey);
        }

        return new Rsa($options);
    }

    /**
     * @throws Rsa\Exception\RuntimeException
     */
    public function __construct(protected RsaOptions $options = new RsaOptions())
    {
        if (! extension_loaded('openssl')) {
            throw new Exception\RuntimeException(
                'Laminas\Crypt\PublicKey\Rsa requires openssl extension to be loaded'
            );
        }
    }

    /**
     * Set options
     */
    public function setOptions(RsaOptions $options): static
    {
        $this->options = $options;
        return $this;
    }

    /**
     * Get options
     */
    public function getOptions(): RsaOptions
    {
        return $this->options;
    }

    /**
     * Return last openssl error(s)
     */
    public function getOpensslErrorString(): string
    {
        $message = '';
        while (false !== ($error = openssl_error_string())) {
            $message .= $error . "\n";
        }
        return trim($message);
    }

    /**
     * Sign with private key
     *
     * @throws Rsa\Exception\RuntimeException
     */
    public function sign(string $data, ?Rsa\PrivateKey $privateKey = null): string
    {
        $signature = '';
        if (! $privateKey instanceof PrivateKey) {
            $privateKey = $this->options->getPrivateKey();
        }

        $result = openssl_sign(
            $data,
            $signature,
            $privateKey->getOpensslKeyResource(),
            $this->options->getOpensslSignatureAlgorithm()
        );
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not generate signature; openssl ' . $this->getOpensslErrorString()
            );
        }

        if ($this->options->getBinaryOutput()) {
            return $signature;
        }

        return base64_encode((string) $signature);
    }

    /**
     * Verify signature with public key
     *
     * $signature can be encoded in base64 or not. $mode sets how the input must be processed:
     *  - MODE_AUTO: Check if the $signature is encoded in base64. Not recommended for performance.
     *  - MODE_BASE64: Decode $signature using base64 algorithm.
     *  - MODE_RAW: $signature is not encoded.
     *
     * @see Rsa::MODE_AUTO
     * @see Rsa::MODE_BASE64
     * @see Rsa::MODE_RAW
     *
     * @param  int                $mode Input encoding
     * @throws Rsa\Exception\RuntimeException
     */
    public function verify(
        string $data,
        string $signature,
        ?Rsa\PublicKey $publicKey = null,
        int $mode = self::MODE_AUTO
    ): bool {
        if (! $publicKey instanceof PublicKey) {
            $publicKey = $this->options->getPublicKey();
        }

        switch ($mode) {
            case self::MODE_AUTO:
                // check if data is encoded in Base64
                $output = base64_decode($signature, true);
                if ((false !== $output) && ($signature === base64_encode($output))) {
                    $signature = $output;
                }
                break;
            case self::MODE_BASE64:
                $signature = base64_decode($signature);
                break;
            case self::MODE_RAW:
            default:
                break;
        }

        $result = openssl_verify(
            $data,
            $signature,
            $publicKey->getOpensslKeyResource(),
            $this->options->getOpensslSignatureAlgorithm()
        );
        if (-1 === $result) {
            throw new Exception\RuntimeException(
                'Can not verify signature; openssl ' . $this->getOpensslErrorString()
            );
        }

        return $result === 1;
    }

    /**
     * Encrypt with private/public key
     *
     * @throws Rsa\Exception\InvalidArgumentException
     */
    public function encrypt(string $data, ?Rsa\AbstractKey $key = null): string
    {
        if (! $key instanceof AbstractKey) {
            $key = $this->options->getPublicKey();
        }

        if (! $key instanceof AbstractKey) {
            throw new Exception\InvalidArgumentException('No key specified for the decryption');
        }

        $padding   = $this->getOptions()->getOpensslPadding();
        $encrypted = null === $padding ? $key->encrypt($data) : $key->encrypt($data, $padding);

        if ($this->options->getBinaryOutput()) {
            return $encrypted;
        }

        return base64_encode($encrypted);
    }

    /**
     * Decrypt with private/public key
     *
     * $data can be encoded in base64 or not. $mode sets how the input must be processed:
     *  - MODE_AUTO: Check if the $signature is encoded in base64. Not recommended for performance.
     *  - MODE_BASE64: Decode $data using base64 algorithm.
     *  - MODE_RAW: $data is not encoded.
     *
     * @see Rsa::MODE_AUTO
     * @see Rsa::MODE_BASE64
     * @see Rsa::MODE_RAW
     *
     * @param  int             $mode Input encoding
     * @throws Rsa\Exception\InvalidArgumentException
     */
    public function decrypt(
        string $data,
        ?Rsa\AbstractKey $key = null,
        int $mode = self::MODE_AUTO
    ): string {
        if (! $key instanceof AbstractKey) {
            $key = $this->options->getPrivateKey();
        }

        if (! $key instanceof AbstractKey) {
            throw new Exception\InvalidArgumentException('No key specified for the decryption');
        }

        switch ($mode) {
            case self::MODE_AUTO:
                // check if data is encoded in Base64
                $output = base64_decode($data, true);
                if ((false !== $output) && ($data === base64_encode($output))) {
                    $data = $output;
                }
                break;
            case self::MODE_BASE64:
                $data = base64_decode($data);
                break;
            case self::MODE_RAW:
            default:
                break;
        }

        $padding = $this->getOptions()->getOpensslPadding();
        if (null === $padding) {
            return $key->decrypt($data);
        } else {
            return $key->decrypt($data, $padding);
        }
    }
}
