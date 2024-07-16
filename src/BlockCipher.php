<?php

declare(strict_types=1);

namespace Laminas\Crypt;

use Laminas\Crypt\Key\Derivation\Pbkdf2;
use Laminas\Crypt\Symmetric\SymmetricInterface;
use Laminas\Math\Rand;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface as NotFoundException;

use function base64_decode;
use function base64_encode;
use function class_exists;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use function is_subclass_of;
use function mb_substr;
use function sprintf;

/**
 * Encrypt using a symmetric cipher then authenticate using HMAC (SHA-256)
 */
class BlockCipher
{
    /**
     * Hash algorithm for Pbkdf2
     */
    protected string $pbkdf2Hash = 'sha256';

    /**
     * Symmetric cipher plugin manager
     */
    protected static ?ContainerInterface $symmetricPlugins = null;

    /**
     * Hash algorithm for HMAC
     */
    protected string $hash = 'sha256';

    /**
     * Check if the salt has been set
     */
    protected bool $saltSetted = false;

    /**
     * The output is binary?
     */
    protected bool $binaryOutput = false;

    /**
     * Number of iterations for Pbkdf2
     */
    protected int $keyIteration = 5000;

    /**
     * Key
     */
    protected string $key;

    /**
     * Constructor
     */
    public function __construct(
        /**
         * Symmetric cipher
         */
        protected SymmetricInterface $cipher
    ) {
    }

    /**
     * Factory
     */
    public static function factory(string $adapter, array $options = []): static
    {
        $plugins = static::getSymmetricPluginManager();
        try {
            $cipher = $plugins->get($adapter);
        } catch (NotFoundException) {
            throw new Exception\RuntimeException(sprintf(
                'The symmetric adapter %s does not exist',
                $adapter
            ));
        }
        $cipher->setOptions($options);
        return new static($cipher);
    }

    /**
     * Returns the symmetric cipher plugin manager.  If it doesn't exist it's created.
     */
    public static function getSymmetricPluginManager(): ContainerInterface
    {
        if (! static::$symmetricPlugins instanceof ContainerInterface) {
            static::setSymmetricPluginManager(new SymmetricPluginManager());
        }

        return static::$symmetricPlugins;
    }

    /**
     * Set the symmetric cipher plugin manager
     *
     * @param  string|SymmetricPluginManager      $plugins
     * @throws Exception\InvalidArgumentException
     */
    public static function setSymmetricPluginManager(string|ContainerInterface $plugins): void
    {
        if (is_string($plugins)) {
            if (! class_exists($plugins) || ! is_subclass_of($plugins, ContainerInterface::class)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'Unable to locate symmetric cipher plugins using class "%s"; '
                    . 'class does not exist or does not implement ContainerInterface',
                    $plugins
                ));
            }
            $plugins = new $plugins();
        }
        static::$symmetricPlugins = $plugins;
    }

    /**
     * Set the symmetric cipher
     */
    public function setCipher(SymmetricInterface $cipher): static
    {
        $this->cipher = $cipher;
        return $this;
    }

    /**
     * Get symmetric cipher
     */
    public function getCipher(): SymmetricInterface
    {
        return $this->cipher;
    }

    /**
     * Set the number of iterations for Pbkdf2
     */
    public function setKeyIteration(int $num): static
    {
        $this->keyIteration = $num;

        return $this;
    }

    /**
     * Get the number of iterations for Pbkdf2
     */
    public function getKeyIteration(): int
    {
        return $this->keyIteration;
    }

    /**
     * Set the salt (IV)
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setSalt(string $salt): static
    {
        try {
            $this->cipher->setSalt($salt);
        } catch (Symmetric\Exception\InvalidArgumentException $e) {
            throw new Exception\InvalidArgumentException("The salt is not valid: " . $e->getMessage());
        }
        $this->saltSetted = true;

        return $this;
    }

    /**
     * Get the salt (IV) according to the size requested by the algorithm
     */
    public function getSalt(): string|null
    {
        return $this->cipher->getSalt();
    }

    /**
     * Get the original salt value
     */
    public function getOriginalSalt(): string
    {
        return $this->cipher->getOriginalSalt();
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
     * Set the encryption/decryption key
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setKey(string $key): static
    {
        if ($key === '' || $key === '0') {
            throw new Exception\InvalidArgumentException('The key cannot be empty');
        }
        $this->key = $key;

        return $this;
    }

    /**
     * Get the key
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Set algorithm of the symmetric cipher
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setCipherAlgorithm(string $algo): static
    {
        try {
            $this->cipher->setAlgorithm($algo);
        } catch (Symmetric\Exception\InvalidArgumentException $e) {
            throw new Exception\InvalidArgumentException($e->getMessage());
        }

        return $this;
    }

    /**
     * Get the cipher algorithm
     */
    public function getCipherAlgorithm(): string
    {
        return $this->cipher->getAlgorithm();
    }

    /**
     * Get the supported algorithms of the symmetric cipher
     */
    public function getCipherSupportedAlgorithms(): array
    {
        return $this->cipher->getSupportedAlgorithms();
    }

    /**
     * Set the hash algorithm for HMAC authentication
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setHashAlgorithm(string $hash): static
    {
        if (! Hash::isSupported($hash)) {
            throw new Exception\InvalidArgumentException(
                "The specified hash algorithm '{$hash}' is not supported by Laminas\Crypt\Hash"
            );
        }
        $this->hash = $hash;

        return $this;
    }

    /**
     * Get the hash algorithm for HMAC authentication
     */
    public function getHashAlgorithm(): string
    {
        return $this->hash;
    }

    /**
     * Set the hash algorithm for the Pbkdf2
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setPbkdf2HashAlgorithm(string $hash): static
    {
        if (! Hash::isSupported($hash)) {
            throw new Exception\InvalidArgumentException(
                "The specified hash algorithm '{$hash}' is not supported by Laminas\Crypt\Hash"
            );
        }
        $this->pbkdf2Hash = $hash;

        return $this;
    }

    /**
     * Get the Pbkdf2 hash algorithm
     */
    public function getPbkdf2HashAlgorithm(): string
    {
        return $this->pbkdf2Hash;
    }

    /**
     * Encrypt then authenticate using HMAC
     *
     * @throws Exception\InvalidArgumentException
     */
    public function encrypt(string $data): string
    {
        // 0 (as integer), 0.0 (as float) & '0' (as string) will return false, though these should be allowed
        // Must be a string, integer, or float in order to encrypt
        if (
            (is_string($data) && $data === '')
            || is_array($data)
            || is_object($data)
        ) {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }

        // Cast to string prior to encrypting
        if (! is_string($data)) {
            $data = (string) $data;
        }

        if (! isset($this->key) || ($this->key === '' || $this->key === '0')) {
            throw new Exception\InvalidArgumentException('No key specified for the encryption');
        }
        $keySize = $this->cipher->getKeySize();
        // generate a random salt (IV) if the salt has not been set
        if (! $this->saltSetted) {
            $this->cipher->setSalt(Rand::getBytes($this->cipher->getSaltSize()));
        }

        if (in_array($this->cipher->getMode(), ['ccm', 'gcm'], true)) {
            return $this->encryptViaCcmOrGcm($data, $keySize);
        }

        // generate the encryption key and the HMAC key for the authentication
        $hash = Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $this->getSalt(),
            $this->keyIteration,
            $keySize * 2
        );
        // set the encryption key
        $this->cipher->setKey(mb_substr($hash, 0, $keySize, '8bit'));
        // set the key for HMAC
        $keyHmac = mb_substr($hash, $keySize, null, '8bit');
        // encryption
        $ciphertext = $this->cipher->encrypt($data);
        // HMAC
        $hmac = Hmac::compute($keyHmac, $this->hash, $this->cipher->getAlgorithm() . $ciphertext);

        return $this->binaryOutput ? $hmac . $ciphertext : $hmac . base64_encode($ciphertext);
    }

    /**
     * Decrypt
     *
     * @throws Exception\InvalidArgumentException
     */
    public function decrypt(string $data): string|false
    {
        if (! is_string($data)) {
            throw new Exception\InvalidArgumentException('The data to decrypt must be a string');
        }
        if ('' === $data) {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }
        if (! isset($this->key) || ($this->key === '' || $this->key === '0')) {
            throw new Exception\InvalidArgumentException('No key specified for the decryption');
        }

        $keySize = $this->cipher->getKeySize();

        if (in_array($this->cipher->getMode(), ['ccm', 'gcm'], true)) {
            return $this->decryptViaCcmOrGcm($data, $keySize);
        }

        $hmacSize   = Hmac::getOutputSize($this->hash);
        $hmac       = mb_substr($data, 0, $hmacSize, '8bit');
        $ciphertext = mb_substr($data, $hmacSize, null, '8bit') ?: '';
        if (! $this->binaryOutput) {
            $ciphertext = base64_decode($ciphertext);
        }
        $iv = mb_substr($ciphertext, 0, $this->cipher->getSaltSize(), '8bit');
        // generate the encryption key and the HMAC key for the authentication
        $hash = Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $iv,
            $this->keyIteration,
            $keySize * 2
        );
        // set the decryption key
        $this->cipher->setKey(mb_substr($hash, 0, $keySize, '8bit'));
        // set the key for HMAC
        $keyHmac = mb_substr($hash, $keySize, null, '8bit');
        $hmacNew = Hmac::compute($keyHmac, $this->hash, $this->cipher->getAlgorithm() . $ciphertext);
        if (! Utils::compareStrings($hmacNew, $hmac)) {
            return false;
        }

        return $this->cipher->decrypt($ciphertext);
    }

    /**
     * Note: CCM and GCM modes do not need HMAC
     *
     * @throws Exception\InvalidArgumentException
     */
    private function encryptViaCcmOrGcm(string $data, int $keySize): string
    {
        $this->cipher->setKey(Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $this->getSalt(),
            $this->keyIteration,
            $keySize
        ));

        $cipherText = $this->cipher->encrypt($data);

        return $this->binaryOutput ? $cipherText : base64_encode($cipherText);
    }

    /**
     * Note: CCM and GCM modes do not need HMAC
     *
     * @throws Exception\InvalidArgumentException
     */
    private function decryptViaCcmOrGcm(string $data, int $keySize): string
    {
        $cipherText = $this->binaryOutput ? $data : base64_decode($data);
        $iv         = mb_substr($cipherText, $this->cipher->getTagSize(), $this->cipher->getSaltSize(), '8bit');

        $this->cipher->setKey(Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $iv,
            $this->keyIteration,
            $keySize
        ));

        return $this->cipher->decrypt($cipherText);
    }
}
