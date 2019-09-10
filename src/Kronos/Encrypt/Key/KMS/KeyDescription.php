<?php

namespace Kronos\Encrypt\Key\KMS;

class KeyDescription
{

    /**
     * CiphertextBlob returned by KMS GenerateDataKey
     * @var string
     */
    private $ciphertextBlob;

    /**
     * Encryption context to send along the decryption of the ciphertextblob
     * @var EncryptionContext
     */
    private $context = null;

    /**
     * KeyDescription constructor.
     * @param string $ciphertextBlob
     */
    public function __construct(string $ciphertextBlob)
    {
        $this->ciphertextBlob = $ciphertextBlob;
    }

    /**
     * @return string
     */
    public function getCiphertextBlob(): string
    {
        return $this->ciphertextBlob;
    }

    /**
     * @param EncryptionContext $context
     */
    public function setEncryptionContext(EncryptionContext $context)
    {
        $this->context = $context;
    }

    /**
     * @return EncryptionContext
     */
    public function getEncryptionContext(): EncryptionContext
    {
        return $this->context;
    }

    /**
     * Return encryption context as an array
     * @return array
     */
    public function getEncryptionContextAsArray(): array
    {
        if ($this->context) {
            return $this->context->toArray();
        } else {
            return [];
        }
    }
}
