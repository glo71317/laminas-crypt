<?php
declare(strict_types=1);

namespace LaminasTest\Crypt;

use Laminas\Crypt\Exception\InvalidArgumentException;
use Laminas\Crypt\Hmac;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

use function base64_encode;
use function str_repeat;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

/**
 * @group      Laminas_Crypt
 */
class HmacTest extends TestCase
{
    public function testIsSupportedAndCache()
    {
        $reflectionClass                = new ReflectionClass(Hmac::class);
        $lastAlgorithmSupportedProperty = $reflectionClass->getProperty('lastAlgorithmSupported');
        $lastAlgorithmSupportedProperty->setAccessible(true);

        Hmac::clearLastAlgorithmCache();
        $this->assertEquals(null, $lastAlgorithmSupportedProperty->getValue());

        $algorithm = 'sha512';

        // cache value must be exactly equal to the original input
        $this->assertTrue(Hmac::isSupported($algorithm));
        $this->assertEquals($algorithm, $lastAlgorithmSupportedProperty->getValue());
        $this->assertNotEquals('sHa512', $lastAlgorithmSupportedProperty->getValue());

        // cache value must be exactly equal to the first input (cache hit)
        Hmac::isSupported('sha512');
        $this->assertEquals($algorithm, $lastAlgorithmSupportedProperty->getValue());

        // cache changes with a new algorithm
        $this->assertTrue(Hmac::isSupported('MD5'));
        $this->assertEquals('MD5', $lastAlgorithmSupportedProperty->getValue());

        // cache don't change due wrong algorithm
        $this->assertFalse(Hmac::isSupported('wrong'));
        $this->assertEquals('MD5', $lastAlgorithmSupportedProperty->getValue());

        Hmac::clearLastAlgorithmCache();
        $this->assertEquals(null, $lastAlgorithmSupportedProperty->getValue());
    }

    // MD5 tests taken from RFC 2202

    /**
     * @psalm-return array<array-key, array{
     *     0: string,
     *     1: string,
     *     2: string,
     * }>
     */
    public function provideMd5Data()
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        return [
            ['Hi There', str_repeat("\x0b", 16), '9294727a3638bb1c13f48ef8158bfc9d'],
            ['what do ya want for nothing?', 'Jefe', '750c783e6ab0b503eaa86e310a5db738'],
            [str_repeat("\xdd", 50), str_repeat("\xaa", 16), '56be34521d144c88dbb8c733f0e8b3f6'],
            [
                str_repeat("\xcd", 50),
                "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
                '697eaf0aca3a3aea3a75164746ffaa79',
            ],
            ['Test With Truncation', str_repeat("\x0c", 16), '56461ef2342edc00f9bab995690efd4c'],
            [
                'Test Using Larger Than Block-Size Key - Hash Key First',
                str_repeat("\xaa", 80),
                '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd',
            ],
            [
                'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data',
                str_repeat("\xaa", 80),
                '6f630fad67cda0ee1fb1f562db3aa53e',
            ],
        ];
        // phpcs:enable Generic.Files.LineLength.TooLong
    }

    /**
     * @dataProvider provideMd5Data
     */
    public function testMd5(string $data, string $key, string $output)
    {
        $hash = Hmac::compute($key, 'MD5', $data);
        $this->assertEquals($output, $hash);
    }

    // SHA1 tests taken from RFC 2202

    /**
     * @psalm-return array<array-key, array{
     *     0: string,
     *     1: string,
     *     2: string,
     * }>
     */
    public function provideSha1Data(): array
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        return [
            ['Hi There', str_repeat("\x0b", 20), 'b617318655057264e28bc0b6fb378c8ef146be00'],
            ['what do ya want for nothing?', 'Jefe', 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'],
            [str_repeat("\xdd", 50), str_repeat("\xaa", 20), '125d7342b9ac11cd91a39af48aa17b4f63f175d3'],
            [
                str_repeat("\xcd", 50),
                "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
                '4c9007f4026250c6bc8414f9bf50c86c2d7235da',
            ],
            ['Test With Truncation', str_repeat("\x0c", 20), '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04'],
            [
                'Test Using Larger Than Block-Size Key - Hash Key First',
                str_repeat("\xaa", 80),
                'aa4ae5e15272d00e95705637ce8a3b55ed402112',
            ],
            [
                'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data',
                str_repeat("\xaa", 80),
                'e8e99d0f45237d786d6bbaa7965c7808bbff1a91',
            ],
        ];
        // phpcs:enable Generic.Files.LineLength.TooLong
    }

    /**
     * @dataProvider provideSha1Data
     */
    public function testSha1(string $data, string $key, string $output)
    {
        $hash = Hmac::compute($key, 'SHA1', $data);
        $this->assertEquals($output, $hash);
    }

    // RIPEMD160 tests taken from RFC 2286

    /**
     * @psalm-return array<array-key, array{
     *     0: string,
     *     1: string,
     *     2: string,
     * }>
     */
    public function provideRipemd160Data(): array
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        return [
            ['Hi There', str_repeat("\x0b", 20), '24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668'],
            ['what do ya want for nothing?', 'Jefe', 'dda6c0213a485a9e24f4742064a7f033b43c4069'],
            [str_repeat("\xdd", 50), str_repeat("\xaa", 20), 'b0b105360de759960ab4f35298e116e295d8e7c1'],
            [
                str_repeat("\xcd", 50),
                "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
                'd5ca862f4d21d5e610e18b4cf1beb97a4365ecf4',
            ],
            ['Test With Truncation', str_repeat("\x0c", 20), '7619693978f91d90539ae786500ff3d8e0518e39'],
            [
                'Test Using Larger Than Block-Size Key - Hash Key First',
                str_repeat("\xaa", 80),
                '6466ca07ac5eac29e1bd523e5ada7605b791fd8b',
            ],
            [
                'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data',
                str_repeat("\xaa", 80),
                '69ea60798d71616cce5fd0871e23754cd75d5a0a',
            ],
        ];
        // phpcs:enable Generic.Files.LineLength.TooLong
    }

    /**
     * @dataProvider provideRipemd160Data
     */
    public function testRipemd160(string $data, string $key, string $output)
    {
        $hash = Hmac::compute($key, 'RIPEMD160', $data);
        $this->assertEquals($output, $hash);
    }

    public function testEmptyKey()
    {
        Hmac::clearLastAlgorithmCache();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Provided key is null or empty');
        Hmac::compute(null, 'md5', 'test');
    }

    public function testNullHashAlgorithm()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Hash algorithm is not supported on this PHP installation');
        Hmac::compute('key', null, 'test');
    }

    public function testWrongHashAlgorithm()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Hash algorithm is not supported on this PHP installation');
        Hmac::compute('key', 'wrong', 'test');
    }

    public function testBinaryOutput()
    {
        $data = Hmac::compute('key', 'sha256', 'test', Hmac::OUTPUT_BINARY);
        $this->assertEquals('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', base64_encode($data));
    }
}
