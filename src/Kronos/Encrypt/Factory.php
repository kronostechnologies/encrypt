<?php

namespace Kronos\Encrypt;

use Aws\Kms\KmsClient;
use Kronos\Encrypt\Cipher\CipherAdaptor;
use Kronos\Encrypt\Cipher\AES;
use Kronos\Encrypt\Cipher\None;
use Kronos\Encrypt\Key\Generator\KMS as KmsKeyGenerator;
use Kronos\Encrypt\Key\Generator\RandomBytes;
use Kronos\Encrypt\Key\KMS\EncryptionContext;
use Kronos\Encrypt\Key\KMS\KeyDescription;
use Kronos\Encrypt\Key\Provider\KMS as KmsProvider;
use Kronos\Encrypt\Key\Provider\SimpleKey;

class Factory
{

    /**
     * @return AES
     */
    public function createAESCipher(): AES
    {
        return new AES();
    }

    /**
     * @return None
     */
    public function createPassthroughCipher(): None
    {
        return new None();
    }

    /**
     * @return RandomBytes
     */
    public function createRandomBytesGenerator(): RandomBytes
    {
        return new RandomBytes();
    }

    /**
     * @param string $key
     * @return Key\Provider\SimpleKey
     */
    public function createSimpleKeyProvider($key): SimpleKey
    {
        return new SimpleKey($key);
    }

    /**
     * @param KmsClient $kmsClient
     * @return Key\Generator\KMS
     */
    public function createKMSKeyGenerator(KmsClient $kmsClient): KmsKeyGenerator
    {
        return new KmsKeyGenerator($kmsClient);
    }

    /**
     * @param KmsClient $kmsClient
     * @param string $ciphertextBlob
     * @param array $context
     * @return KmsProvider
     */
    public function createKMSProvider(KmsClient $kmsClient, string $ciphertextBlob, array $context = []): KmsProvider
    {
        $keyDescription = new Key\KMS\KeyDescription($ciphertextBlob);
        if (count($context)) {
            $encryptionContext = new Key\KMS\EncryptionContext();
            foreach ($context as $field => $value) {
                $encryptionContext->addField($field, $value);
            }
            $keyDescription->setEncryptionContext($encryptionContext);
        }
        return new KmsProvider($kmsClient, $keyDescription);
    }

    /**
     * @param string $ciphertextBlob
     * @return KeyDescription
     */
    public function createKMSKeyDescription($ciphertextBlob): KeyDescription
    {
        return new KeyDescription($ciphertextBlob);
    }

    /**
     * @return EncryptionContext
     */
    public function createKMSEncryptionContext(): EncryptionContext
    {
        return new EncryptionContext();
    }

    /**
     * @param Cipher\CipherAdaptor $cipher
     * @param Key\Provider\ProviderAdaptor $provider
     * @return Encrypt
     */
    public function createEncrypt(CipherAdaptor $cipher, Key\Provider\ProviderAdaptor $provider)
    {
        return new Encrypt($cipher, $provider);
    }
}
