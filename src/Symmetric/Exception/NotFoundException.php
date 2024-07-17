<?php

declare(strict_types=1);

namespace Laminas\Crypt\Symmetric\Exception;

use Laminas\Crypt\Exception;

/**
 * Not found exception
 */
class NotFoundException extends Exception\NotFoundException implements ExceptionInterface
{
}
