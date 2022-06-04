<?php

namespace Kronos\Encrypt\Key\KMS;

class EncryptionContext
{
    private array $context = [];

    public function addField(string $field, string $value): void
    {
        if ($field) {
            $this->context[$field] = $value;
        }
    }

    public function toArray(): array
    {
        return $this->context;
    }
}
