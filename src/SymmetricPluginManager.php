<?php

namespace Laminas\Crypt;

use Psr\Container\ContainerInterface;

use function array_key_exists;
use function sprintf;

/**
 * Plugin manager implementation for the symmetric adapter instances.
 *
 * Enforces that symmetric adapters retrieved are instances of
 * Symmetric\SymmetricInterface. Additionally, it registers a number of default
 * symmetric adapters available.
 */
final class SymmetricPluginManager implements ContainerInterface
{
    /**
     * Default set of symmetric adapters
     *
     * @var array
     */
    protected $symmetric = [
        'mcrypt'  => Symmetric\Mcrypt::class,
        'openssl' => Symmetric\Openssl::class,
    ];

    /**
     * Do we have the symmetric plugin?
     */
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->symmetric);
    }

    /**
     * Retrieve the symmetric plugin
     *
     * @return Symmetric\SymmetricInterface
     */
    public function get(string $id)
    {
        if (! $this->has($id)) {
            throw new Exception\NotFoundException(sprintf(
                'The symmetric adapter %s does not exist',
                $id
            ));
        }
        $class = $this->symmetric[$id];
        return new $class();
    }
}
