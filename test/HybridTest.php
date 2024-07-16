<?php

declare(strict_types=1);

namespace LaminasTest\Crypt;

use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Exception;
use Laminas\Crypt\Hybrid;
use Laminas\Crypt\PublicKey\Rsa;
use Laminas\Crypt\PublicKey\RsaOptions;
use PHPUnit\Framework\TestCase;

use function extension_loaded;

class HybridTest extends TestCase
{
    protected Hybrid $hybrid;

    public function setUp(): void
    {
        if (! extension_loaded('openssl')) {
            $this->markTestSkipped('The OpenSSL extension is required');
        }
        $this->hybrid = new Hybrid();
    }

    public function testConstructor(): void
    {
        $hybrid = new Hybrid();
        $this->assertInstanceOf(Hybrid::class, $hybrid);
    }

    public function testConstructorWithParameters(): void
    {
        $hybrid = new Hybrid(
            $this->createMock(BlockCipher::class),
            $this->createMock(Rsa::class),
        );
        $this->assertInstanceOf(Hybrid::class, $hybrid);
    }

    public function testGetDefaultBlockCipherInstance(): void
    {
        $bCipher = $this->hybrid->getBlockCipherInstance();
        $this->assertInstanceOf(BlockCipher::class, $bCipher);
    }

    public function testGetDefaultRsaInstance(): void
    {
        $rsa = $this->hybrid->getRsaInstance();
        $this->assertInstanceOf(Rsa::class, $rsa);
    }

    public function testEncryptDecryptWithOneStringKey(): void
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey()->toString();
        $privateKey = $rsaOptions->getPrivateKey()->toString();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptDecryptWithOneStringKeyAndPassphrase(): void
    {
        $passPhrase = 'test';
        $rsaOptions = new RsaOptions([
            'pass_phrase' => $passPhrase,
        ]);
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey()->toString();
        $privateKey = $rsaOptions->getPrivateKey()->toString();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey, $passPhrase);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleStringKeys(): void
    {
        $publicKeys  = [];
        $privateKeys = [];
        $rsaOptions  = new RsaOptions();

        for ($id = 0; $id < 5; $id++) {
            $rsaOptions->generateKeys([
                'private_key_bits' => 1024,
            ]);
            $publicKeys[$id]  = $rsaOptions->getPublicKey()->toString();
            $privateKeys[$id] = $rsaOptions->getPrivateKey()->toString();
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], null, (string) $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    public function testEncryptDecryptWithOneObjectKey(): void
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey();
        $privateKey = $rsaOptions->getPrivateKey();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleObjectKeys(): void
    {
        $publicKeys  = [];
        $privateKeys = [];
        $rsaOptions  = new RsaOptions();

        for ($id = 0; $id < 5; $id++) {
            $rsaOptions->generateKeys([
                'private_key_bits' => 1024,
            ]);
            $publicKeys[$id]  = $rsaOptions->getPublicKey();
            $privateKeys[$id] = $rsaOptions->getPrivateKey();
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], null, (string) $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    public function testFailToDecryptWithOneKey(): void
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey = $rsaOptions->getPublicKey();
        // Generate a new private key
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $privateKey = $rsaOptions->getPrivateKey();

        // encrypt using a single key
        $encrypted = $this->hybrid->encrypt('test', $publicKey);

        $this->expectException(Exception\RuntimeException::class);
        // try to decrypt using a different private key throws an exception
        $this->hybrid->decrypt($encrypted, $privateKey);
    }

    public function testFailToEncryptUsingPrivateKey(): void
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $privateKey = $rsaOptions->getPrivateKey();

        $this->expectException(Exception\RuntimeException::class);
        // encrypt using a PrivateKey object throws an exception
        $this->hybrid->encrypt('test', $privateKey);
    }
}
