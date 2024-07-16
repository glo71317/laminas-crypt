<?php

declare(strict_types=1);

namespace Laminas\Crypt\Symmetric\Padding;

/**
 * No Padding
 */
class NoPadding implements PaddingInterface
{
    /**
     * Pad a string, do nothing and return the string
     */
    public function pad(string $string, int $blockSize = 32): string
    {
        return $string;
    }

    /**
     * Unpad a string, do nothing and return the string
     *
     * @return string
     */
    public function strip(string $string): string|false
    {
        return $string;
    }
}
