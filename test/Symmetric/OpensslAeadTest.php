<?php
declare(strict_types=1);

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Exception\InvalidArgumentException;
use Laminas\Crypt\Symmetric\Exception\RuntimeException;
use Laminas\Crypt\Symmetric\Openssl;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

use function chr;
use function mb_strlen;
use function mb_substr;
use function rand;
use function random_bytes;

/**
 * This is a set of unit tests for OpenSSL Authenticated Encrypt with Associated Data (AEAD)
 * support from PHP 7.1+
 */
class OpensslAeadTest extends TestCase
{
    /** @var Openssl */
    private $crypt;

    public function setUp(): void
    {
        $this->crypt = new Openssl();

        if (! $this->crypt->isAuthEncAvailable()) {
            $this->markTestSkipped('Authenticated encryption is not available on this platform');
        }
    }

    public function testConstructByParams()
    {
        $params = [
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 'foo@bar.com',
            'tag_size' => 14,
        ];
        $crypt  = new Openssl($params);

        $this->assertEquals($params['algo'], $crypt->getAlgorithm());
        $this->assertEquals($params['mode'], $crypt->getMode());
        $this->assertEquals($params['aad'], $crypt->getAad());
        $this->assertEquals($params['tag_size'], $crypt->getTagSize());
    }

    public function testRejectsNonStringAadMode()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The provided $aad must be a string, integer given');

        new Openssl([
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 123, // invalid, on purpose
            'tag_size' => 14,
        ]);
    }

    public function testRejectsNonIntegerTagSize()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The provided $size must be an integer, double given');

        new Openssl([
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 'foo@bar.com',
            'tag_size' => 14.5, // invalid, on purpose
        ]);
    }

    public function testSetGetAad()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setAad('foo@bar.com');
        $this->assertEquals('foo@bar.com', $this->crypt->getAad());
    }

    public function testSetAadException()
    {
        $this->crypt->setMode('cbc');

        $this->expectException(RuntimeException::class);
        $this->crypt->setAad('foo@bar.com');
    }

    public function testSetGetGcmTagSize()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setTagSize(10);
        $this->assertEquals(10, $this->crypt->getTagSize());
    }

    public function testSetGetCcmTagSize()
    {
        $this->crypt->setMode('ccm');
        $this->crypt->setTagSize(28);
        $this->assertEquals(28, $this->crypt->getTagSize());
    }

    public function testSetTagSizeException()
    {
        $this->crypt->setMode('cbc');

        $this->expectException(RuntimeException::class);
        $this->crypt->setTagSize(10);
    }

    public function testSetInvalidGcmTagSize()
    {
        $this->crypt->setMode('gcm');

        $this->expectException(InvalidArgumentException::class);
        $this->crypt->setTagSize(18); // gcm supports tag size between 4 and 16
    }

    /** @psalm-return array<array-key, array{0: string}> */
    public function getAuthEncryptionMode(): array
    {
        return [
            ['gcm'],
            ['ccm'],
        ];
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticatedEncryption(string $mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);
        $tag       = $this->crypt->getTag();

        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($tag, '8bit'));
        $this->assertEquals(mb_substr($encrypt, 0, $this->crypt->getTagSize(), '8bit'), $tag);

        $decrypt = $this->crypt->decrypt($encrypt);
        $tag2    = $this->crypt->getTag();
        $this->assertEquals($tag, $tag2);
        $this->assertEquals($plaintext, $decrypt);
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticationError(string $mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);

        // Alter the encrypted message
        // phpcs:disable SlevomatCodingStandard.Operators.RequireCombinedAssignmentOperator.RequiredCombinedAssigmentOperator
        $i           = rand(0, mb_strlen($encrypt, '8bit') - 1);
        $encrypt[$i] = $encrypt[$i] ^ chr(1);
        // phpcs:enable SlevomatCodingStandard.Operators.RequireCombinedAssignmentOperator.RequiredCombinedAssigmentOperator

        $this->expectException(RuntimeException::class);
        $this->crypt->decrypt($encrypt);
    }

    public function testGcmEncryptWithTagSize()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setTagSize(14);

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);
        $this->assertEquals(14, $this->crypt->getTagSize());
        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($this->crypt->getTag(), '8bit'));
    }

    public function testCcmEncryptWithTagSize()
    {
        $this->crypt->setMode('ccm');
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setTagSize(14);

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);
        $this->assertEquals(14, $this->crypt->getTagSize());
        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($this->crypt->getTag(), '8bit'));
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticatedEncryptionWithAdditionalData(string $mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setAad('foo@bar.com');

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);
        $tag       = $this->crypt->getTag();

        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($tag, '8bit'));
        $this->assertEquals(mb_substr($encrypt, 0, $this->crypt->getTagSize(), '8bit'), $tag);

        $decrypt = $this->crypt->decrypt($encrypt);
        $tag2    = $this->crypt->getTag();
        $this->assertEquals($tag, $tag2);
        $this->assertEquals($plaintext, $decrypt);
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticationErrorOnAdditionalData(string $mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setAad('foo@bar.com');

        $plaintext = Rand::getBytes(1024);
        $encrypt   = $this->crypt->encrypt($plaintext);

        // Alter the additional authentication data
        $this->crypt->setAad('foo@baz.com');

        $this->expectException(RuntimeException::class);

        $this->crypt->decrypt($encrypt);
    }
}
