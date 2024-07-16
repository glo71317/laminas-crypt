<?php
declare(strict_types=1);

namespace LaminasTest\Crypt\Key\Derivation;

use Laminas\Crypt\Key\Derivation\Exception;
use Laminas\Crypt\Key\Derivation\Pbkdf2;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function bin2hex;
use function sprintf;
use function strlen;

class Pbkdf2Test extends TestCase
{
    /** @var string */
    public $salt;

    public function setUp(): void
    {
        $this->salt = '12345678901234567890123456789012';
    }

    public function testCalc()
    {
        $password = Pbkdf2::calc('sha256', 'test', $this->salt, 5000, 32);
        $this->assertEquals(32, strlen($password));
        $this->assertEquals('JVNgHc1AeBl/S9H6Jo2tUUi838snakDBMcsNJP0+0O0=', base64_encode($password));
    }

    public function testCalcWithWrongHash()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The hash algorithm wrong is not supported by %s',
            Pbkdf2::class
        ));
        Pbkdf2::calc('wrong', 'test', $this->salt, 5000, 32);
    }

    /**
     * Test vectors from RFC 6070
     *
     * @see http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
     *
     * @psalm-return array<array-key, array{
     *     0: string,
     *     1: string,
     *     2: string,
     *     3: int,
     *     4: int,
     *     5: string,
     * }>
     */
    public static function provideTestVectors(): array
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        return [
            ['sha1', 'password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'],
            ['sha1', 'password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'],
            ['sha1', 'password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'],
            ['sha1', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'],
            ['sha1', "pass\0word", "sa\0lt", 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'],
        ];
        // phpcs:enable Generic.Files.LineLength.TooLong
    }

    /**
     * @dataProvider provideTestVectors
     */
    public function testRFC670(string $hash, string $password, string $salt, int $cycles, int $length, string $expect)
    {
        $result = Pbkdf2::calc($hash, $password, $salt, $cycles, $length);
        $this->assertEquals($expect, bin2hex($result));
    }
}
