<?php

declare(strict_types=1);

namespace Laminas\Crypt\Symmetric\Padding;

interface PaddingInterface
{
    /**
     * Pad the string to the specified size
     *
     * @param  string $string    The string to pad
     * @param  int    $blockSize The size to pad to
     * @return string The padded string
     */
    public function pad(string $string, int $blockSize = 32): string;

    /**
     * Strip the padding from the supplied string
     *
     * @param  string $string The string to trim
     * @return string The unpadded string
     */
    public function strip(string $string): string|false;
}
