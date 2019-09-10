<?php

namespace Kronos\Encrypt\Key\KMS;

class EncryptionContext
{

    private $context = [];

    /**
     * @param $field string Name of the field to add
     * @param $value string Value of the field to add
     */
    public function addField(string $field, string $value): void
    {
        if ($field) {
            $this->context[$field] = $value;
        }
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->context;
    }
}
