<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\BlockCipher;

use Exception as GlobalException;
use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Exception;
use Laminas\Crypt\Symmetric;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

use function file_get_contents;
use function in_array;
use function preg_match;
use function sprintf;
use function str_repeat;
use function substr;

use const OPENSSL_VERSION_TEXT;

abstract class AbstractBlockCipherTestcase extends TestCase
{
    /** @var Symmetric\SymmetricInterface */
    protected $cipher;

    /** @var BlockCipher */
    protected $blockCipher;

    /** @var string */
    protected $plaintext;

    /** @var string[] */
    // phpcs:ignore WebimpressCodingStandard.NamingConventions.ValidVariableName.NotCamelCapsProperty
    protected $unsupportedOpenSSL3Algos = [
        'blowfish',
        'cast5',
        'des',
        'seed',
    ];

    public function setUp(): void
    {
        $this->assertInstanceOf(
            Symmetric\SymmetricInterface::class,
            $this->cipher,
            'Symmetric adapter instance is needed for tests'
        );
        $this->blockCipher = new BlockCipher($this->cipher);
        $this->plaintext   = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testSetKey(): void
    {
        $result = $this->blockCipher->setKey('test');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('test', $this->blockCipher->getKey());
    }

    public function testSetEmptyKey(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setKey('');
    }

    public function testSetSalt(): void
    {
        $salt   = str_repeat('a', $this->blockCipher->getCipher()->getSaltSize() + 2);
        $result = $this->blockCipher->setSalt($salt);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals(
            substr($salt, 0, $this->blockCipher->getCipher()->getSaltSize()),
            $this->blockCipher->getSalt()
        );
        $this->assertEquals($salt, $this->blockCipher->getOriginalSalt());
    }

    public function testSetWrongSalt(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSalt('x');
    }

    public function testSetAlgorithm(): void
    {
        $result = $this->blockCipher->setCipherAlgorithm('aes');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('aes', $this->blockCipher->getCipherAlgorithm());
    }

    public function testSetAlgorithmFail(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The algorithm unknown is not supported by %s',
            $this->cipher::class
        ));
        $this->blockCipher->setCipherAlgorithm('unknown');
    }

    public function testSetHashAlgorithm(): void
    {
        $result = $this->blockCipher->setHashAlgorithm('sha1');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('sha1', $this->blockCipher->getHashAlgorithm());
    }

    public function testSetUnsupportedHashAlgorithm(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setHashAlgorithm('foo');
    }

    public function testSetPbkdf2HashAlgorithm(): void
    {
        $result = $this->blockCipher->setPbkdf2HashAlgorithm('sha1');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('sha1', $this->blockCipher->getPbkdf2HashAlgorithm());
    }

    public function testSetUnsupportedPbkdf2HashAlgorithm(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setPbkdf2HashAlgorithm('foo');
    }

    public function testSetKeyIteration(): void
    {
        $result = $this->blockCipher->setKeyIteration(1000);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals(1000, $this->blockCipher->getKeyIteration());
    }

    public function testEncryptWithoutData(): void
    {
        $plaintext = '';
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to encrypt cannot be empty');
        $this->blockCipher->encrypt($plaintext);
    }

    public function testEncryptErrorKey(): void
    {
        $plaintext = 'test';
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('No key specified for the encryption');
        $this->blockCipher->encrypt($plaintext);
    }

    public function testEncryptDecrypt(): void
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            if (
                in_array($algo, $this->unsupportedOpenSSL3Algos, true)
                && preg_match('/^OpenSSL 3/', OPENSSL_VERSION_TEXT)
            ) {
                // Skipping, as unsupported in OpenSSL 3
                continue;
            }

            $this->blockCipher->setCipherAlgorithm($algo);
            try {
                $encrypted = $this->blockCipher->encrypt($this->plaintext);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed encryption using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertNotEmpty($encrypted);
            try {
                $decrypted = $this->blockCipher->decrypt($encrypted);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed decrypting using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertEquals($decrypted, $this->plaintext);
        }
    }

    public function testEncryptDecryptUsingBinary(): void
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        $this->blockCipher->setBinaryOutput(true);
        $this->assertTrue($this->blockCipher->getBinaryOutput());

        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            if (
                in_array($algo, $this->unsupportedOpenSSL3Algos, true)
                && preg_match('/^OpenSSL 3/', OPENSSL_VERSION_TEXT)
            ) {
                // Skipping, as unsupported in OpenSSL 3
                continue;
            }

            $this->blockCipher->setCipherAlgorithm($algo);
            try {
                $encrypted = $this->blockCipher->encrypt($this->plaintext);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed encryption using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertNotEmpty($encrypted);
            try {
                $decrypted = $this->blockCipher->decrypt($encrypted);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed decrypting using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertEquals($decrypted, $this->plaintext);
        }
    }

    /** @psalm-return array<string, array{0: int|float|string}> */
    public static function zeroValuesProvider(): array
    {
        return [
            '"0.0"' => [0.0],
            '"0"'   => ['0'],
        ];
    }

    /**
     * @dataProvider zeroValuesProvider
     */
    public function testEncryptDecryptUsingZero(int|float|string $value): void
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            if (
                in_array($algo, $this->unsupportedOpenSSL3Algos, true)
                && preg_match('/^OpenSSL 3/', OPENSSL_VERSION_TEXT)
            ) {
                // Skipping, as unsupported in OpenSSL 3
                continue;
            }

            $this->blockCipher->setCipherAlgorithm($algo);

            try {
                $encrypted = $this->blockCipher->encrypt((string) $value);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed encryption using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertNotEmpty($encrypted);
            try {
                $decrypted = $this->blockCipher->decrypt($encrypted);
            } catch (GlobalException $e) {
                $this->fail(sprintf('Failed decrypting using %s: %s', $algo, $e->getMessage()));
            }
            $this->assertEquals($value, $decrypted);
        }
    }

    public function testDecryptEmptyString(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->decrypt('');
    }

    public function testDecyptWihoutKey(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->decrypt('encrypted data');
    }

    public function testDecryptAuthFail(): void
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        $encrypted = $this->blockCipher->encrypt($this->plaintext);
        $this->assertNotEmpty($encrypted);
        // tamper the encrypted data
        $encrypted = substr($encrypted, -1);
        $decrypted = $this->blockCipher->decrypt($encrypted);
        $this->assertFalse($decrypted);
    }

    public function testSetSymmetricPluginManager(): void
    {
        $old = $this->blockCipher->getSymmetricPluginManager();

        $this->blockCipher->setSymmetricPluginManager(
            $this->getMockBuilder(ContainerInterface::class)->getMock()
        );
        $this->assertInstanceOf(ContainerInterface::class, $this->blockCipher->getSymmetricPluginManager());

        $this->blockCipher->setSymmetricPluginManager($old);
    }

    public function testFactoryWithWrongAdapter(): void
    {
        $this->expectException(Exception\RuntimeException::class);
        $this->blockCipher = BlockCipher::factory('foo');
    }

    public function testSetWrongSymmetricPluginManager(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSymmetricPluginManager(stdClass::class);
    }

    public function testSetNotExistingSymmetricPluginManager(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSymmetricPluginManager('Foo');
    }
}
