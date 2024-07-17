<?php

declare(strict_types=1);

namespace LaminasTest\Crypt\FileCipher;

use Laminas\Crypt\FileCipher;
use Laminas\Crypt\Symmetric;
use Laminas\Crypt\Symmetric\Openssl;
use Laminas\Crypt\Symmetric\SymmetricInterface;

class OpensslTestcase extends AbstractFileCipherTestcase
{
    public function setUp(): void
    {
        try {
            $this->fileCipher = new FileCipher(new Openssl());
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testDefaultCipher(): void
    {
        $fileCipher = new FileCipher();
        $this->assertInstanceOf(Openssl::class, $fileCipher->getCipher());
    }

    public function testSetCipher(): void
    {
        $cipher = new Openssl([
            'algo' => 'aes',
        ]);
        $this->fileCipher->setCipher($cipher);
        $this->assertInstanceOf(SymmetricInterface::class, $this->fileCipher->getCipher());
        $this->assertEquals($cipher, $this->fileCipher->getCipher());
    }
}
