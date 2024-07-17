<?php

declare(strict_types=1);

namespace Laminas\Crypt;

use function hash;
use function hash_algos;
use function in_array;
use function strtolower;

class Hash
{
    public const OUTPUT_STRING = false;
    public const OUTPUT_BINARY = true;

    /**
     * Last algorithm supported
     */
    protected static ?string $lastAlgorithmSupported = null;

    /**
     * @throws Exception\InvalidArgumentException
     */
    public static function compute(string $hash, string $data, bool $output = self::OUTPUT_STRING): string
    {
        if ($hash !== static::$lastAlgorithmSupported && ! static::isSupported($hash)) {
            throw new Exception\InvalidArgumentException(
                'Hash algorithm provided is not supported on this PHP installation'
            );
        }

        return hash($hash, $data, $output);
    }

    /**
     * Get the supported algorithm
     */
    public static function getSupportedAlgorithms(): array
    {
        return hash_algos();
    }

    /**
     * Is the hash algorithm supported?
     */
    public static function isSupported(string $algorithm): bool
    {
        if ($algorithm === static::$lastAlgorithmSupported) {
            return true;
        }

        if (in_array(strtolower($algorithm), hash_algos(), true)) {
            static::$lastAlgorithmSupported = $algorithm;
            return true;
        }

        return false;
    }

    /**
     * Clear the cache of last algorithm supported
     */
    public static function clearLastAlgorithmCache(): void
    {
        static::$lastAlgorithmSupported = null;
    }
}
