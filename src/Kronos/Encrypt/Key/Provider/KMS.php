<?php

namespace Kronos\Encrypt\Key\Provider;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\Exception\FetchException;
use Kronos\Encrypt\Key\KMS\KeyDescription;

class KMS implements ProviderAdaptor
{
    /**
     * @var KmsClient
     */
    private $client;

    /**
     * @var KeyDescription
     */
    private $key_description;

    private string $decrypted_key = '';

    /**
     * @param KmsClient $client
     * @param KeyDescription $key_description
     */
    public function __construct(KmsClient $client, KeyDescription $key_description)
    {
        $this->client = $client;
        $this->key_description = $key_description;
    }

    /**
     * Return KMS decrypted key
     * @throws FetchException
     */
    public function getKey(): string
    {
        if (empty($this->decrypted_key)) {

            $decoded_ciphertextblob = base64_decode($this->key_description->getCiphertextBlob(), true);
            if (!$decoded_ciphertextblob) {
                throw new FetchException('CiphertextBlob should be a valid base64 encoded string');
            }

            $options = [
                'CiphertextBlob' => $decoded_ciphertextblob
            ];

            $context = $this->key_description->getEncryptionContextAsArray();
            if (!empty($context)) {
                $options['EncryptionContext'] = $context;
            }

            try {
                $response = $this->client->decrypt($options);
            } catch (KmsException $e) {
                throw new FetchException('Key decryption failed', 0, $e);
            }

            $decryptedKey = is_string($response['Plaintext']) ? $response['Plaintext'] : '';
            $this->decrypted_key = $decryptedKey;
        }

        return $this->decrypted_key;
    }
}
