<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\BlockCipher;

use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Symmetric;

class OpensslTestcase extends AbstractBlockCipherTestcase
{
    public function setUp(): void
    {
        try {
            $this->cipher = new Symmetric\Openssl([
                'algorithm' => 'aes',
                'mode'      => 'cbc',
                'padding'   => 'pkcs7',
            ]);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testSetCipher(): void
    {
        new Symmetric\Openssl();
        $result = $this->blockCipher->setCipher($this->cipher);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals($this->cipher, $this->blockCipher->getCipher());
    }

    public function testFactory(): void
    {
        $this->blockCipher = BlockCipher::factory('openssl', ['algo' => 'aes']);
        $this->assertInstanceOf(Symmetric\Openssl::class, $this->blockCipher->getCipher());
        $this->assertEquals('aes', $this->blockCipher->getCipher()->getAlgorithm());
    }

    public function testFactoryEmptyOptions(): void
    {
        $this->blockCipher = BlockCipher::factory('openssl');
        $this->assertInstanceOf(Symmetric\Openssl::class, $this->blockCipher->getCipher());
    }
}
