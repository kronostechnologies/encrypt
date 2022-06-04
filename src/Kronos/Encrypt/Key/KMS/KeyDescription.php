<?php

namespace Kronos\Encrypt\Key\KMS;

class KeyDescription
{

    /**
     * CiphertextBlob returned by KMS GenerateDataKey
     */
    private string $ciphertextBlob;

    /**
     * Encryption context to send along the decryption of the ciphertextblob
     */
    private ?EncryptionContext $context = null;

    public function __construct(string $ciphertextBlob)
    {
        $this->ciphertextBlob = $ciphertextBlob;
    }

    public function getCiphertextBlob(): string
    {
        return $this->ciphertextBlob;
    }

    public function setEncryptionContext(EncryptionContext $context): void
    {
        $this->context = $context;
    }

    public function getEncryptionContext(): ?EncryptionContext
    {
        return $this->context;
    }

    public function getEncryptionContextAsArray(): array
    {
        if ($this->context) {
            return $this->context->toArray();
        } else {
            return [];
        }
    }
}
