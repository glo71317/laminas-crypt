<?php

declare(strict_types=1);

namespace Laminas\Crypt\Key\Derivation\Exception;

use Laminas\Crypt\Exception;

/**
 * Invalid argument exception
 */
class InvalidArgumentException extends Exception\InvalidArgumentException implements
    ExceptionInterface
{
}
