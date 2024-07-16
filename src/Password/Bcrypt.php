<?php

declare(strict_types=1);

namespace Laminas\Crypt\Password;

use Laminas\Stdlib\ArrayUtils;
use Traversable;

use function is_array;
use function microtime;
use function password_hash;
use function password_verify;
use function sprintf;
use function strtolower;

use const PASSWORD_BCRYPT;

/**
 * Bcrypt algorithm using crypt() function of PHP
 */
class Bcrypt implements PasswordInterface
{
    public const MIN_SALT_SIZE = 22;

    protected string $cost = '10';

    protected string $salt;

    /**
     * Constructor
     *
     * @throws Exception\InvalidArgumentException
     */
    public function __construct(Traversable|array $options = [])
    {
        if (! empty($options)) {
            if ($options instanceof Traversable) {
                $options = ArrayUtils::iteratorToArray($options);
            }

            if (! is_array($options)) {
                throw new Exception\InvalidArgumentException(
                    'The options parameter must be an array or a Traversable'
                );
            }

            foreach ($options as $key => $value) {
                switch (strtolower($key)) {
                    case 'salt':
                        $this->setSalt($value);
                        break;
                    case 'cost':
                        $this->setCost($value);
                        break;
                }
            }
        }
    }

    /**
     * Bcrypt
     *
     * @throws Exception\RuntimeException
     */
    public function create(string $password): string
    {
        $options = ['cost' => (int) $this->cost];
        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    /**
     * Verify if a password is correct against a hash value
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Set the cost parameter
     *
     * @throws Exception\InvalidArgumentException
     */
    public function setCost(int|string $cost): static
    {
        if ($cost !== 0 && ($cost !== '' && $cost !== '0')) {
            $cost = (int) $cost;
            if ($cost < 4 || $cost > 31) {
                throw new Exception\InvalidArgumentException(
                    'The cost parameter of bcrypt must be in range 04-31'
                );
            }
            $this->cost = sprintf('%1$02d', $cost);
        }
        return $this;
    }

    /**
     * Get the cost parameter
     */
    public function getCost(): string
    {
        return $this->cost;
    }

    /**
     * Benchmark the bcrypt hash generation to determine the cost parameter based on time to target.
     *
     * The default time to test is 50 milliseconds which is a good baseline for
     * systems handling interactive logins. If you increase the time, you will
     * get high cost with better security, but potentially expose your system
     * to DoS attacks.
     *
     * @see php.net/manual/en/function.password-hash.php#refsect1-function.password-hash-examples
     *
     * @param float $timeTarget Defaults to 50ms (0.05)
     * @return int Maximum cost value that falls within the time to target.
     */
    public function benchmarkCost(float $timeTarget = 0.05): int
    {
        $cost = 8;

        do {
            $cost++;
            $start = microtime(true);
            password_hash('test', PASSWORD_BCRYPT, ['cost' => $cost]);
            $end = microtime(true);
        } while (($end - $start) < $timeTarget);

        return $cost;
    }
}
