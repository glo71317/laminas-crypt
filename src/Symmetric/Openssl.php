<?php

declare(strict_types=1);

namespace Laminas\Crypt\Symmetric;

use ArrayAccess;
use Laminas\Crypt\Symmetric\Padding\PaddingInterface;
use Laminas\Stdlib\ArrayUtils;
use Psr\Container\ContainerInterface;
use Traversable;

use function class_exists;
use function extension_loaded;
use function in_array;
use function is_array;
use function is_string;
use function is_subclass_of;
use function mb_strlen;
use function mb_substr;
use function openssl_cipher_iv_length;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;
use function openssl_get_cipher_methods;
use function sprintf;
use function strtolower;

use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;
use const PHP_VERSION_ID;

/**
 * Symmetric encryption using the OpenSSL extension
 *
 * NOTE: DO NOT USE only this class to encrypt data.
 * This class doesn't provide authentication and integrity check over the data.
 * PLEASE USE Laminas\Crypt\BlockCipher instead!
 */
class Openssl implements SymmetricInterface
{
    public const DEFAULT_PADDING = 'pkcs7';

    /**
     * Key
     */
    protected string $key;

    /**
     * IV
     */
    protected string $iv;

    /**
     * Encryption algorithm
     */
    protected string $algo = 'aes';

    /**
     * Encryption mode
     */
    protected string $mode = 'cbc';

    /**
     * Padding
     */
    protected Padding\PaddingInterface|null $padding;

    /**
     * Padding plugins
     */
    protected static ?ContainerInterface $paddingPlugins = null;

    /**
     * The encryption algorithms to support
     *
     * @var array
     */
    protected $encryptionAlgos = [
        'aes'      => 'aes-256',
        'blowfish' => 'bf',
        'des'      => 'des',
        'camellia' => 'camellia-256',
        'cast5'    => 'cast5',
        'seed'     => 'seed',
    ];

    /**
     * Encryption modes to support
     *
     * @var array
     */
    protected $encryptionModes = [
        'cbc',
        'cfb',
        'ofb',
        'ecb',
        'ctr',
    ];

    /**
     * Block sizes (in bytes) for each supported algorithm
     *
     * @var array
     */
    protected $blockSizes = [
        'aes'      => 16,
        'blowfish' => 8,
        'des'      => 8,
        'camellia' => 16,
        'cast5'    => 8,
        'seed'     => 16,
    ];

    /**
     * Key sizes (in bytes) for each supported algorithm
     *
     * @var array
     */
    protected $keySizes = [
        'aes'      => 32,
        'blowfish' => 56,
        'des'      => 8,
        'camellia' => 32,
        'cast5'    => 16,
        'seed'     => 16,
    ];

    /**
     * The OpenSSL supported encryption algorithms
     */
    protected array $opensslAlgos = [];

    /**
     * Additional authentication data (only for PHP 7.1+)
     */
    protected string $aad = '';

    /**
     * Store the tag for authentication (only for PHP 7.1+)
     */
    protected ?string $tag = null;

    /**
     * Tag size for authenticated encryption modes (only for PHP 7.1+)
     */
    protected int $tagSize = 16;

    /**
     * Supported algorithms
     *
     * @internal This property was declared for compatibility with PHP 8.2,
     *          and is not supposed to be used directly, other than for BC reasons
     *
     * @var list<string>
     */
    public array $supportedAlgos = [];

    /**
     * Constructor
     *
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function __construct(Traversable|array $options = [])
    {
        if (! extension_loaded('openssl')) {
            throw new Exception\RuntimeException(sprintf(
                'You cannot use %s without the OpenSSL extension',
                self::class
            ));
        }
        $this->encryptionModes[] = 'gcm';
        $this->encryptionModes[] = 'ccm';
        $this->setOptions($options);
        $this->setDefaultOptions($options);
    }

    /**
     * Set default options
     *
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function setOptions(Traversable|array $options): void
    {
        if (empty($options)) {
            return;
        }

        if ($options instanceof Traversable) {
            $options = ArrayUtils::iteratorToArray($options);
        }

        if (! is_array($options)) {
            throw new Exception\InvalidArgumentException(
                'The options parameter must be an array or a Traversable'
            );
        }

        // The algorithm case is not included in the switch because must be
        // set before the others
        if (isset($options['algo'])) {
            $this->setAlgorithm($options['algo']);
        } elseif (isset($options['algorithm'])) {
            $this->setAlgorithm($options['algorithm']);
        }

        foreach ($options as $key => $value) {
            switch (strtolower($key)) {
                case 'mode':
                    $this->setMode($value);
                    break;
                case 'key':
                    $this->setKey($value);
                    break;
                case 'iv':
                case 'salt':
                    $this->setSalt($value);
                    break;
                case 'padding':
                    $plugins       = static::getPaddingPluginManager();
                    $padding       = $plugins->get($value);
                    $this->padding = $padding;
                    break;
                case 'aad':
                    $this->setAad($value);
                    break;
                case 'tag_size':
                    $this->setTagSize($value);
                    break;
            }
        }
    }

    /**
     * Set default options
     */
    protected function setDefaultOptions(array|ArrayAccess $options = []): void
    {
        if (isset($options['padding'])) {
            return;
        }

        $plugins       = static::getPaddingPluginManager();
        $padding       = $plugins->get(self::DEFAULT_PADDING);
        $this->padding = $padding;
    }

    /**
     * Returns the padding plugin manager.
     *
     * Creates one if none is present.
     */
    public static function getPaddingPluginManager(): ContainerInterface
    {
        if (! static::$paddingPlugins instanceof ContainerInterface) {
            self::setPaddingPluginManager(new PaddingPluginManager());
        }

        return static::$paddingPlugins;
    }

    /**
     * Set the padding plugin manager
     *
     * @throws Exception\InvalidArgumentException
     */
    public static function setPaddingPluginManager(string|ContainerInterface $plugins): void
    {
        if (is_string($plugins)) {
            if (! class_exists($plugins) || ! is_subclass_of($plugins, ContainerInterface::class)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'Unable to locate padding plugin manager via class "%s"; '
                    . 'class does not exist or does not implement ContainerInterface',
                    $plugins
                ));
            }

            $plugins = new $plugins();
        }

        static::$paddingPlugins = $plugins;
    }

    /**
     * Get the key size for the selected cipher
     */
    public function getKeySize(): int
    {
        return $this->keySizes[$this->algo];
    }

    /**
     * Set the encryption key
     * If the key is longer than maximum supported, it will be truncated by getKey().
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setKey(string $key): static
    {
        $keyLen = mb_strlen($key, '8bit');

        if ($keyLen === 0) {
            throw new Exception\InvalidArgumentException('The key cannot be empty');
        }

        if ($keyLen < $this->getKeySize()) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The size of the key must be at least of %d bytes',
                $this->getKeySize()
            ));
        }

        $this->key = $key;
        return $this;
    }

    /**
     * Get the encryption key
     */
    public function getKey(): ?string
    {
        if (! isset($this->key) || ($this->key === '' || $this->key === '0')) {
            return null;
        }
        return mb_substr($this->key, 0, $this->getKeySize(), '8bit');
    }

    /**
     * Set the encryption algorithm (cipher)
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setAlgorithm(string $algo): static
    {
        if (! in_array($algo, $this->getSupportedAlgorithms())) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The algorithm %s is not supported by %s',
                $algo,
                self::class
            ));
        }
        $this->algo = $algo;
        return $this;
    }

    /**
     * Get the encryption algorithm
     */
    public function getAlgorithm(): string
    {
        return $this->algo;
    }

    /**
     * Set the padding object
     */
    public function setPadding(PaddingInterface $padding): static
    {
        $this->padding = $padding;
        return $this;
    }

    /**
     * Get the padding object
     */
    public function getPadding(): PaddingInterface
    {
        return $this->padding;
    }

    /**
     * Set Additional Authentication Data
     *
     * @throws Exception\InvalidArgumentException
     * @throws Exception\RuntimeException
     */
    public function setAad(string $aad): static
    {
        if (! $this->isAuthEncAvailable()) {
            throw new Exception\RuntimeException(
                'You need PHP 7.1+ and OpenSSL with CCM or GCM mode to use AAD'
            );
        }

        if (! $this->isCcmOrGcm()) {
            throw new Exception\RuntimeException(
                'You can set Additional Authentication Data (AAD) only for CCM or GCM mode'
            );
        }

        $this->aad = $aad;

        return $this;
    }

    /**
     * Get the Additional Authentication Data
     */
    public function getAad(): string
    {
        return $this->aad;
    }

    /**
     * Get the authentication tag
     */
    public function getTag(): string|null
    {
        return $this->tag;
    }

    /**
     * Set the tag size for CCM and GCM mode
     *
     * @throws Exception\InvalidArgumentException
     * @throws Exception\RuntimeException
     */
    public function setTagSize(int $size): static
    {
        if (! $this->isAuthEncAvailable()) {
            throw new Exception\RuntimeException(
                'You need PHP 7.1+ and OpenSSL with CCM or GCM mode to set the Tag Size'
            );
        }

        if (! $this->isCcmOrGcm()) {
            throw new Exception\RuntimeException(
                'You can set the Tag Size only for CCM or GCM mode'
            );
        }

        if ($this->getMode() === 'gcm' && ($size < 4 || $size > 16)) {
            throw new Exception\InvalidArgumentException(
                'The Tag Size must be between 4 to 16 for GCM mode'
            );
        }

        $this->tagSize = $size;

        return $this;
    }

    /**
     * Get the tag size for CCM and GCM mode
     */
    public function getTagSize(): int
    {
        return $this->tagSize;
    }

    /**
     * Encrypt
     *
     * @throws Exception\InvalidArgumentException
     */
    public function encrypt(string $data): string
    {
        // Cannot encrypt empty string
        if ($data === '') {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }

        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No key specified for the encryption');
        }

        if (null === $this->getSalt() && $this->getSaltSize() > 0) {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }

        if (! $this->getPadding() instanceof PaddingInterface) {
            throw new Exception\InvalidArgumentException('You must specify a padding method');
        }

        // padding
        $data = $this->padding->pad($data, $this->getBlockSize());
        $iv   = $this->getSalt();

        // encryption with GCM or CCM
        if ($this->isCcmOrGcm()) {
            $result    = openssl_encrypt(
                $data,
                strtolower($this->encryptionAlgos[$this->algo] . '-' . $this->mode),
                $this->getKey(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv,
                $tag,
                $this->getAad(),
                $this->getTagSize()
            );
            $this->tag = $tag;
        } else {
            $result = openssl_encrypt(
                $data,
                strtolower($this->encryptionAlgos[$this->algo] . '-' . $this->mode),
                $this->getKey(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv
            );
        }

        if (false === $result) {
            $errMsg = '';
            while ($msg = openssl_error_string()) {
                $errMsg .= $msg;
            }
            throw new Exception\RuntimeException(sprintf(
                'OpenSSL error: %s',
                $errMsg
            ));
        }

        if ($this->isCcmOrGcm()) {
            return $tag . $iv . $result;
        }

        return $iv . $result;
    }

    /**
     * Decrypt
     *
     * @throws Exception\InvalidArgumentException
     */
    public function decrypt(string $data): string
    {
        if ($data === '' || $data === '0') {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }

        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No decryption key specified');
        }
        if (! $this->getPadding() instanceof PaddingInterface) {
            throw new Exception\InvalidArgumentException('You must specify a padding method');
        }

        if ($this->isCcmOrGcm()) {
            $tag       = mb_substr($data, 0, $this->getTagSize(), '8bit');
            $data      = mb_substr($data, $this->getTagSize(), null, '8bit');
            $this->tag = $tag;
        }

        $iv         = mb_substr($data, 0, $this->getSaltSize(), '8bit');
        $ciphertext = mb_substr($data, $this->getSaltSize(), null, '8bit');
        $result     = $this->attemptOpensslDecrypt($ciphertext, $iv, $this->tag);

        if (false === $result) {
            $errMsg = '';

            while ($msg = openssl_error_string()) {
                $errMsg .= $msg;
            }

            throw new Exception\RuntimeException(sprintf(
                'OpenSSL error: %s',
                $errMsg
            ));
        }

        // unpadding
        return $this->padding->strip($result);
    }

    /**
     * Get the salt (IV) size
     */
    public function getSaltSize(): int|false
    {
        return openssl_cipher_iv_length(
            $this->encryptionAlgos[$this->algo] . '-' . $this->mode
        );
    }

    /**
     * Get the supported algorithms
     */
    public function getSupportedAlgorithms(): array
    {
        if ($this->supportedAlgos === []) {
            foreach ($this->encryptionAlgos as $name => $algo) {
                // CBC mode is supported by all the algorithms
                if (in_array($algo . '-cbc', $this->getOpensslAlgos())) {
                    $this->supportedAlgos[] = $name;
                }
            }
        }
        return $this->supportedAlgos;
    }

    /**
     * Set the salt (IV)
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setSalt(string $salt): static
    {
        if ($this->getSaltSize() <= 0) {
            throw new Exception\InvalidArgumentException(sprintf(
                'You cannot use a salt (IV) for %s in %s mode',
                $this->algo,
                $this->mode
            ));
        }

        if ($salt === '' || $salt === '0') {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }

        if (mb_strlen($salt, '8bit') < $this->getSaltSize()) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The size of the salt (IV) must be at least %d bytes',
                $this->getSaltSize()
            ));
        }

        $this->iv = $salt;
        return $this;
    }

    /**
     * Get the salt (IV) according to the size requested by the algorithm
     */
    public function getSalt(): ?string
    {
        if (! isset($this->iv) || ($this->iv === '' || $this->iv === '0')) {
            return null;
        }

        if (mb_strlen($this->iv, '8bit') < $this->getSaltSize()) {
            throw new Exception\RuntimeException(sprintf(
                'The size of the salt (IV) must be at least %d bytes',
                $this->getSaltSize()
            ));
        }

        return mb_substr($this->iv, 0, $this->getSaltSize(), '8bit');
    }

    /**
     * Get the original salt value
     */
    public function getOriginalSalt(): string
    {
        return $this->iv;
    }

    /**
     * Set the cipher mode
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setMode(string $mode): static
    {
        if ($mode === '' || $mode === '0') {
            return $this;
        }
        if (! in_array($mode, $this->getSupportedModes())) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The mode %s is not supported by %s',
                $mode,
                $this->algo
            ));
        }
        $this->mode = $mode;
        return $this;
    }

    /**
     * Get the cipher mode
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    /**
     * Return the OpenSSL supported encryption algorithms
     */
    protected function getOpensslAlgos(): array
    {
        if ($this->opensslAlgos === []) {
            $this->opensslAlgos = openssl_get_cipher_methods(true);
        }
        return $this->opensslAlgos;
    }

    /**
     * Get all supported encryption modes for the selected algorithm
     */
    public function getSupportedModes(): array
    {
        $modes = [];
        foreach ($this->encryptionModes as $mode) {
            $algo = $this->encryptionAlgos[$this->algo] . '-' . $mode;
            if (in_array($algo, $this->getOpensslAlgos())) {
                $modes[] = $mode;
            }
        }
        return $modes;
    }

    /**
     * Get the block size
     */
    public function getBlockSize(): int
    {
        return $this->blockSizes[$this->algo];
    }

    /**
     * Return true if authenticated encryption is available
     */
    public function isAuthEncAvailable(): bool
    {
        // Counter with CBC-MAC
        $ccm = in_array('aes-256-ccm', $this->getOpensslAlgos());
        // Galois/Counter Mode
        $gcm = in_array('aes-256-gcm', $this->getOpensslAlgos());

        return PHP_VERSION_ID >= 70100 && ($ccm || $gcm);
    }

    private function isCcmOrGcm(): bool
    {
        return in_array(strtolower($this->mode), ['gcm', 'ccm'], true);
    }

    private function attemptOpensslDecrypt(string $cipherText, string $iv, string|null $tag): string|false
    {
        if ($this->isCcmOrGcm()) {
            return openssl_decrypt(
                $cipherText,
                strtolower($this->encryptionAlgos[$this->algo] . '-' . $this->mode),
                $this->getKey(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv,
                $tag,
                $this->getAad()
            );
        }

        return openssl_decrypt(
            $cipherText,
            strtolower($this->encryptionAlgos[$this->algo] . '-' . $this->mode),
            $this->getKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
    }
}
