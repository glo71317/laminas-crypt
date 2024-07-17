<?php

declare(strict_types=1);

namespace Laminas\Crypt;

use Laminas\Crypt\Key\Derivation\Pbkdf2;
use Laminas\Crypt\Symmetric\SymmetricInterface;
use Laminas\Math\Rand;

use function fclose;
use function file_exists;
use function filesize;
use function fopen;
use function fread;
use function fseek;
use function fwrite;
use function mb_strlen;
use function mb_substr;
use function sprintf;
use function str_repeat;
use function unlink;

/**
 * Encrypt/decrypt a file using a symmetric cipher in CBC mode
 * then authenticate using HMAC
 */
class FileCipher
{
    public const BUFFER_SIZE = 1048576; // 16 * 65536 bytes = 1 Mb
    /**
     * Hash algorithm for Pbkdf2
     */
    protected string $pbkdf2Hash = 'sha256';

    /**
     * Hash algorithm for HMAC
     */
    protected string $hash = 'sha256';

    /**
     * Number of iterations for Pbkdf2
     */
    protected int $keyIteration = 10000;

    /**
     * Key
     */
    protected string $key;

    /**
     * Cipher
     */
    protected ?SymmetricInterface $cipher;

    /**
     * Constructor
     */
    public function __construct(?Symmetric\SymmetricInterface $cipher = null)
    {
        if (! $cipher instanceof SymmetricInterface) {
            $cipher = new Symmetric\Openssl();
        }
        $this->cipher = $cipher;
    }

    /**
     * Set the cipher object
     */
    public function setCipher(SymmetricInterface $cipher): void
    {
        $this->cipher = $cipher;
    }

    /**
     * Get the cipher object
     */
    public function getCipher(): ?SymmetricInterface
    {
        return $this->cipher;
    }

    /**
     * Set the number of iterations for Pbkdf2
     */
    public function setKeyIteration(int $num): void
    {
        $this->keyIteration = $num;
    }

    /**
     * Get the number of iterations for Pbkdf2
     */
    public function getKeyIteration(): int
    {
        return $this->keyIteration;
    }

    /**
     * Set the encryption/decryption key
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setKey(string $key): void
    {
        if ($key === '' || $key === '0') {
            throw new Exception\InvalidArgumentException('The key cannot be empty');
        }
        $this->key = $key;
    }

    /**
     * Get the key
     */
    public function getKey(): string|null
    {
        return $this->key;
    }

    /**
     * Set algorithm of the symmetric cipher
     */
    public function setCipherAlgorithm(string $algo): void
    {
        $this->cipher->setAlgorithm($algo);
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
    public function setHashAlgorithm(string $hash): void
    {
        if (! Hash::isSupported($hash)) {
            throw new Exception\InvalidArgumentException(
                "The specified hash algorithm '{$hash}' is not supported by Laminas\Crypt\Hash"
            );
        }
        $this->hash = $hash;
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
    public function setPbkdf2HashAlgorithm(string $hash): void
    {
        if (! Hash::isSupported($hash)) {
            throw new Exception\InvalidArgumentException(
                "The specified hash algorithm '{$hash}' is not supported by Laminas\Crypt\Hash"
            );
        }
        $this->pbkdf2Hash = $hash;
    }

    /**
     * Get the Pbkdf2 hash algorithm
     */
    public function getPbkdf2HashAlgorithm(): string
    {
        return $this->pbkdf2Hash;
    }

    /**
     * Encrypt then authenticate a file using HMAC
     *
     * @throws Exception\InvalidArgumentException
     */
    public function encrypt(string $fileIn, string $fileOut): bool
    {
        $this->checkFileInOut($fileIn, $fileOut);
        if (! isset($this->key) || ($this->key === '' || $this->key === '0')) {
            throw new Exception\InvalidArgumentException('No key specified for encryption');
        }

        $read    = fopen($fileIn, "r");
        $write   = fopen($fileOut, "w");
        $iv      = Rand::getBytes($this->cipher->getSaltSize());
        $keys    = Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $iv,
            $this->getKeyIteration(),
            $this->cipher->getKeySize() * 2
        );
        $hmac    = '';
        $size    = 0;
        $tot     = filesize($fileIn);
        $padding = $this->cipher->getPadding();

        $this->cipher->setKey(mb_substr($keys, 0, $this->cipher->getKeySize(), '8bit'));
        $this->cipher->setPadding(new Symmetric\Padding\NoPadding());
        $this->cipher->setSalt($iv);
        $this->cipher->setMode('cbc');

        $hashAlgo  = $this->getHashAlgorithm();
        $saltSize  = $this->cipher->getSaltSize();
        $algorithm = $this->cipher->getAlgorithm();
        $keyHmac   = mb_substr($keys, $this->cipher->getKeySize(), null, '8bit');

        while ($data = fread($read, self::BUFFER_SIZE)) {
            $size += mb_strlen($data, '8bit');
            // Padding if last block
            if ($size === $tot) {
                $this->cipher->setPadding($padding);
            }
            $result = $this->cipher->encrypt($data);
            if ($size <= self::BUFFER_SIZE) {
                // Write a placeholder for the HMAC and write the IV
                fwrite($write, str_repeat('0', Hmac::getOutputSize($hashAlgo)));
            } else {
                $result = mb_substr($result, $saltSize, null, '8bit');
            }
            $hmac = Hmac::compute(
                $keyHmac,
                $hashAlgo,
                $algorithm . $hmac . $result
            );
            $this->cipher->setSalt(mb_substr($result, -1 * $saltSize, null, '8bit'));
            if (fwrite($write, $result) !== mb_strlen($result, '8bit')) {
                return false;
            }
        }
        $result = true;
        // write the HMAC at the beginning of the file
        fseek($write, 0);
        if (fwrite($write, $hmac) !== mb_strlen($hmac, '8bit')) {
            $result = false;
        }
        fclose($write);
        fclose($read);

        return $result;
    }

    /**
     * Decrypt a file
     *
     * @throws Exception\InvalidArgumentException
     */
    public function decrypt(string $fileIn, string $fileOut): bool
    {
        $this->checkFileInOut($fileIn, $fileOut);
        if (! isset($this->key) || ($this->key === '' || $this->key === '0')) {
            throw new Exception\InvalidArgumentException('No key specified for decryption');
        }

        $read     = fopen($fileIn, "r");
        $write    = fopen($fileOut, "w");
        $hmacRead = fread($read, Hmac::getOutputSize($this->getHashAlgorithm()));
        $iv       = fread($read, $this->cipher->getSaltSize());
        $tot      = filesize($fileIn);
        $hmac     = $iv;
        $size     = mb_strlen($iv, '8bit') + mb_strlen($hmacRead, '8bit');
        $keys     = Pbkdf2::calc(
            $this->getPbkdf2HashAlgorithm(),
            $this->getKey(),
            $iv,
            $this->getKeyIteration(),
            $this->cipher->getKeySize() * 2
        );
        $padding  = $this->cipher->getPadding();
        $this->cipher->setPadding(new Symmetric\Padding\NoPadding());
        $this->cipher->setKey(mb_substr($keys, 0, $this->cipher->getKeySize(), '8bit'));
        $this->cipher->setMode('cbc');

        $blockSize = $this->cipher->getBlockSize();
        $hashAlgo  = $this->getHashAlgorithm();
        $algorithm = $this->cipher->getAlgorithm();
        $saltSize  = $this->cipher->getSaltSize();
        $keyHmac   = mb_substr($keys, $this->cipher->getKeySize(), null, '8bit');

        while ($data = fread($read, self::BUFFER_SIZE)) {
            $size += mb_strlen($data, '8bit');
            // Unpadding if last block
            if ($size + $blockSize >= $tot) {
                $this->cipher->setPadding($padding);
                $data .= fread($read, $blockSize);
            }
            $result = $this->cipher->decrypt($iv . $data);
            $hmac   = Hmac::compute(
                $keyHmac,
                $hashAlgo,
                $algorithm . $hmac . $data
            );
            $iv     = mb_substr($data, -1 * $saltSize, null, '8bit');
            if (fwrite($write, $result) !== mb_strlen($result, '8bit')) {
                return false;
            }
        }
        fclose($write);
        fclose($read);

        // check for data integrity
        if (! Utils::compareStrings($hmac, $hmacRead)) {
            unlink($fileOut);
            return false;
        }

        return true;
    }

    /**
     * Check that input file exists and output file don't
     *
     * @throws Exception\InvalidArgumentException
     */
    protected function checkFileInOut(string $fileIn, string $fileOut): void
    {
        if (! file_exists($fileIn)) {
            throw new Exception\InvalidArgumentException(sprintf(
                'I cannot open the %s file',
                $fileIn
            ));
        }
        if (file_exists($fileOut)) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The file %s already exists',
                $fileOut
            ));
        }
    }
}
