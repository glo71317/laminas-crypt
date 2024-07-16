<?php

declare(strict_types=1);

namespace Laminas\Crypt\Symmetric;

use Traversable;

interface SymmetricInterface
{
    public function encrypt(string $data): string;

    public function decrypt(string $data): string;

    public function setKey(string $key): static;

    /**
     * @return string
     */
    public function getKey(): string|null;

    public function getKeySize(): int;

    public function getAlgorithm(): string;

    public function setAlgorithm(string $algo): static;

    public function getSupportedAlgorithms(): array;

    public function setSalt(string $salt): static;

    public function getSalt(): ?string;

    public function getSaltSize(): int|false;

    public function getBlockSize(): int;

    public function setMode(string $mode): static;

    public function getMode(): string;

    public function getSupportedModes(): array;

    /**
     * @param array $options
     */
    public function setOptions(Traversable|array $options);
}
