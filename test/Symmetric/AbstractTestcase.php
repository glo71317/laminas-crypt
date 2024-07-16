<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\Symmetric;

use ArrayObject;
use Laminas\Crypt\Symmetric\Exception;
use Laminas\Crypt\Symmetric\Padding\NoPadding;
use Laminas\Crypt\Symmetric\Padding\PKCS7;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use stdClass;
use TypeError;

use function file_get_contents;
use function in_array;
use function mb_strlen;
use function mb_substr;
use function preg_match;
use function sprintf;
use function str_repeat;

use const OPENSSL_VERSION_TEXT;

/**
 * @group      Laminas_Crypt
 */
abstract class AbstractTestcase extends TestCase
{
    /** @var string */
    protected $adapterClass = '';
    /** @var object */
    protected $crypt;
    /** @var string */
    protected $plaintext;
    /** @var string */
    protected $defaultAlgo;
    /** @var string */
    protected $defaultMode;
    /** @var string */
    protected $defaultPadding;

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
        try {
            $this->crypt = new $this->adapterClass();
        } catch (Exception\RuntimeException) {
            $this->markTestSkipped(
                sprintf("%s is not installed, I cannot execute %s", $this->adapterClass, static::class)
            );
        }
        $this->plaintext = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testConstructByParams(): void
    {
        $key     = $this->generateKey();
        $iv      = $this->generateSalt();
        $options = [
            'algorithm' => $this->defaultAlgo,
            'mode'      => $this->defaultMode,
            'key'       => $key,
            'salt'      => $iv,
            'padding'   => $this->defaultPadding,
        ];
        $crypt   = new $this->adapterClass($options);
        $this->assertEquals($crypt->getAlgorithm(), $options['algorithm']);
        $this->assertEquals($crypt->getMode(), $options['mode']);
        $this->assertEquals($crypt->getKey(), mb_substr($key, 0, $crypt->getKeySize(), '8bit'));
        $this->assertEquals($crypt->getSalt(), mb_substr((string) $iv, 0, $crypt->getSaltSize(), '8bit'));
        $this->assertInstanceOf(PKCS7::class, $crypt->getPadding());
    }

    /**
     * This test uses ArrayObject to simulate a Laminas\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig(): void
    {
        $key     = $this->generateKey();
        $iv      = $this->generateSalt();
        $options = [
            'algorithm' => $this->defaultAlgo,
            'mode'      => $this->defaultMode,
            'key'       => $key,
            'salt'      => $iv,
            'padding'   => $this->defaultPadding,
        ];
        $config  = new ArrayObject($options);
        $crypt   = new $this->adapterClass($config);
        $this->assertEquals($crypt->getAlgorithm(), $options['algorithm']);
        $this->assertEquals($crypt->getMode(), $options['mode']);
        $this->assertEquals($crypt->getKey(), mb_substr($key, 0, $crypt->getKeySize(), '8bit'));
        $this->assertEquals($crypt->getSalt(), mb_substr((string) $iv, 0, $crypt->getSaltSize(), '8bit'));
        $this->assertInstanceOf(PKCS7::class, $crypt->getPadding());
    }

    public function testConstructWrongParam(): void
    {
        $options = 'test';
        $this->expectException(TypeError::class);
        $this->expectExceptionMessage('($options) must be of type Traversable|array, string given');
        new $this->adapterClass($options);
    }

    public function testSetAlgorithm(): void
    {
        $this->crypt->setAlgorithm($this->defaultAlgo);
        $this->assertEquals($this->crypt->getAlgorithm(), $this->defaultAlgo);
    }

    public function testSetWrongAlgorithm(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The algorithm test is not supported by %s',
            $this->adapterClass
        ));
        $this->crypt->setAlgorithm('test');
    }

    public function testSetKey(): void
    {
        $key    = $this->generateKey();
        $result = $this->crypt->setKey($key);
        $this->assertInstanceOf($this->adapterClass, $result);
        $this->assertEquals($result, $this->crypt);
        $this->assertEquals($key, $this->crypt->getKey());
    }

    public function testSetEmptyKey(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key cannot be empty');
        $this->crypt->setKey('');
    }

    public function testSetShortKey(): void
    {
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            $this->crypt->setAlgorithm($algo);
            try {
                $this->crypt->setKey('four');
            } catch (\Exception $ex) {
                $this->assertInstanceOf(
                    Exception\InvalidArgumentException::class,
                    $ex
                );
            }
        }
    }

    public function testSetSalt(): void
    {
        $iv = $this->generateSalt() . $this->generateSalt();
        $this->crypt->setSalt($iv);
        $this->assertEquals(
            mb_substr($iv, 0, mb_strlen($iv, '8bit') / 2, '8bit'),
            $this->crypt->getSalt()
        );
        $this->assertEquals($iv, $this->crypt->getOriginalSalt());
    }

    public function testShortSalt(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setSalt('short');
    }

    public function testSetMode(): void
    {
        $this->crypt->setMode($this->defaultMode);
        $this->assertEquals($this->defaultMode, $this->crypt->getMode());
    }

    public function testSetWrongMode(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The mode xxx is not supported by %s',
            $this->crypt->getAlgorithm()
        ));
        $this->crypt->setMode('xxx');
    }

    public function testEncryptDecrypt(): void
    {
        $this->crypt->setPadding(new PKCS7());
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            if (
                in_array($algo, $this->unsupportedOpenSSL3Algos, true)
                && preg_match('/^OpenSSL 3/', OPENSSL_VERSION_TEXT)
            ) {
                // Skipping, as unsupported in OpenSSL 3
                continue;
            }

            foreach ($this->crypt->getSupportedModes() as $mode) {
                $this->crypt->setAlgorithm($algo);
                try {
                    $this->crypt->setMode($mode);
                } catch (\Exception) {
                    // Continue if the encryption mode is not supported for the algorithm
                    continue;
                }
                $this->crypt->setKey($this->generateKey());
                if ($this->crypt->getSaltSize() > 0) {
                    $this->crypt->setSalt($this->generateSalt());
                }

                $encrypted = $this->crypt->encrypt($this->plaintext);
                $this->assertNotEmpty($encrypted);

                $decrypted = $this->crypt->decrypt($encrypted);
                $this->assertNotFalse($decrypted);
                $this->assertEquals($this->plaintext, $decrypted);
            }
        }
    }

    public function testEncryptWithoutKey(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->encrypt('test');
    }

    public function testEncryptEmptyData(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to encrypt cannot be empty');
        $this->crypt->encrypt('');
    }

    public function testEncryptWithoutSalt(): void
    {
        $this->crypt->setKey($this->generateKey());
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The salt (IV) cannot be empty');
        $this->crypt->encrypt($this->plaintext);
    }

    public function testDecryptEmptyData(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to decrypt cannot be empty');
        $this->crypt->decrypt('');
    }

    public function testDecryptWithoutKey(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->decrypt($this->plaintext);
    }

    public function testSetOptions(): void
    {
        $options = [
            'algo' => $this->defaultAlgo,
            'mode' => $this->defaultMode,
        ];
        $this->crypt->setOptions($options);

        $this->assertEquals($options['algo'], $this->crypt->getAlgorithm());
        $this->assertEquals($options['mode'], $this->crypt->getMode());

        $options = [
            'key'     => str_repeat('x', $this->crypt->getKeySize()),
            'iv'      => str_repeat('1', $this->crypt->getSaltSize()),
            'padding' => 'nopadding',
        ];
        $this->crypt->setOptions($options);

        $this->assertEquals($options['key'], $this->crypt->getKey());
        $this->assertEquals($options['iv'], $this->crypt->getSalt());
        $this->assertInstanceOf(NoPadding::class, $this->crypt->getPadding());
    }

    public function testSetPaddingPluginManager(): void
    {
        $this->crypt->setPaddingPluginManager(
            $this->getMockBuilder(ContainerInterface::class)->getMock()
        );
        $this->assertInstanceOf(ContainerInterface::class, $this->crypt->getPaddingPluginManager());
    }

    public function testSetWrongPaddingPluginManager(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setPaddingPluginManager(stdClass::class);
    }

    public function testSetNotExistingPaddingPluginManager(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setPaddingPluginManager('Foo');
    }

    protected function generateKey(): string
    {
        return Rand::getBytes($this->crypt->getKeySize());
    }

    protected function generateSalt(): ?string
    {
        if ($this->crypt->getSaltSize() > 0) {
            return Rand::getBytes($this->crypt->getSaltSize());
        }

        return null;
    }
}
