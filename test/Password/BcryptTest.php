<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\Password;

use ArrayObject;
use Laminas\Crypt\Password\Bcrypt;
use Laminas\Crypt\Password\Exception;
use PHPUnit\Framework\TestCase;

use function chr;
use function strlen;
use function substr;

/**
 * @group      Laminas_Crypt
 */
class BcryptTest extends TestCase
{
    /** @var Bcrypt */
    public $bcrypt;

    /** @var string */
    public $bcryptPassword;

    /** @var string */
    public $password;

    /** @var string */
    protected $prefix;

    public function setUp(): void
    {
        $this->bcrypt   = new Bcrypt();
        $this->password = 'test';
        $this->prefix   = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$123456789012345678901uIcehzOq0s9RvVtyXJFIsuuxuE2XZRMq';
    }

    public function testConstructByOptions(): void
    {
        $options = ['cost' => '15'];
        $bcrypt  = new Bcrypt($options);
        $this->assertEquals('15', $bcrypt->getCost());
    }

    /**
     * This test uses ArrayObject to simulate a Laminas\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig(): void
    {
        $options = ['cost' => '15'];
        $config  = new ArrayObject($options);
        $bcrypt  = new Bcrypt($config);
        $this->assertEquals('15', $bcrypt->getCost());
    }

    public function testSetCost(): void
    {
        $this->bcrypt->setCost('16');
        $this->assertEquals('16', $this->bcrypt->getCost());
    }

    public function testSetWrongCost(): void
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The cost parameter of bcrypt must be in range 04-31');
        $this->bcrypt->setCost('3');
    }

    public function testCreateWithBuiltinSalt(): void
    {
        $password = $this->bcrypt->create('test');
        $this->assertNotEmpty($password);
        $this->assertEquals(60, strlen($password));
    }

    public function testVerify(): void
    {
        $this->assertTrue($this->bcrypt->verify($this->password, $this->bcryptPassword));
        $this->assertFalse($this->bcrypt->verify(substr($this->password, -1), $this->bcryptPassword));
    }

    public function testPasswordWith8bitCharacter(): void
    {
        $password = 'test' . chr(128);
        $hash     = $this->bcrypt->create($password);

        $this->assertNotEmpty($hash);
        $this->assertEquals(60, strlen($hash));
        $this->assertTrue($this->bcrypt->verify($password, $hash));
    }

    public function testBenchmarkCost(): void
    {
        $cost = $this->bcrypt->benchmarkCost();
        $this->assertIsInt($cost);
        $this->assertTrue($cost > 8 && $cost < 32);
    }
}
