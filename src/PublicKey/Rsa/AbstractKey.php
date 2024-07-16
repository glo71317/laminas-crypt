<?php

declare(strict_types=1);

namespace Laminas\Crypt\PublicKey\Rsa;

use Stringable;

abstract class AbstractKey implements Stringable
{
    public const DEFAULT_KEY_SIZE = 2048;

    /**
     * PEM formatted key
     */
    protected string $pemString;

    /**
     * Key Resource
     *
     * @var resource
     */
    protected $opensslKeyResource;

    /**
     * Openssl details array
     */
    protected array $details = [];

    /**
     * Retrieve openssl key resource
     *
     * @return resource
     */
    public function getOpensslKeyResource()
    {
        return $this->opensslKeyResource;
    }

    /**
     * Encrypt using this key
     *
     * @abstract
     */
    abstract public function encrypt(string $data): string;

    /**
     * Decrypt using this key
     *
     * @abstract
     */
    abstract public function decrypt(string $data): string;

    /**
     * Get string representation of this key
     *
     * @abstract
     */
    abstract public function toString(): string;

    public function __toString(): string
    {
        return $this->toString();
    }
}
