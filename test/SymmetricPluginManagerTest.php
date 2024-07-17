<?php

declare(strict_types=1);

namespace LaminasTest\Crypt;

use Laminas\Crypt\Exception as CryptException;
use Laminas\Crypt\Symmetric\Exception;
use Laminas\Crypt\Symmetric\SymmetricInterface;
use Laminas\Crypt\SymmetricPluginManager;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

use function extension_loaded;

class SymmetricPluginManagerTest extends TestCase
{
    /** @psalm-return array<array-key, array{0: string}> */
    public static function getSymmetrics(): array
    {
        return [
            ['openssl'],
        ];
    }

    public function testConstruct(): void
    {
        $plugin = new SymmetricPluginManager();
        $this->assertInstanceOf(ContainerInterface::class, $plugin);
    }

    /**
     * @dataProvider getSymmetrics
     */
    public function testHas(string $symmetric): void
    {
        $plugin = new SymmetricPluginManager();
        $this->assertTrue($plugin->has($symmetric));
    }

    /**
     * @dataProvider getSymmetrics
     */
    public function testGet(string $symmetric): void
    {
        if (! extension_loaded($symmetric)) {
            $this->expectException(Exception\RuntimeException::class);
        }
        $plugin = new SymmetricPluginManager();
        $this->assertInstanceOf(SymmetricInterface::class, $plugin->get($symmetric));
    }

    public function testGetError(): void
    {
        $plugin = new SymmetricPluginManager();

        $this->expectException(CryptException\NotFoundException::class);
        $plugin->get('foo');
    }
}
