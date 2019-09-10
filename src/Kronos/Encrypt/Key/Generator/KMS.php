<?php

namespace Kronos\Encrypt\Key\Generator;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\Exception\GenerateException;
use Kronos\Encrypt\Key\KMS\EncryptionContext;
use Kronos\Encrypt\Key\KMS\KeyDescription;

class KMS
{

    /**
     * @var KmsClient
     */
    private $kms_client;

    /**
     * KMS key generator constructor.
     * @param KmsClient $kms_client
     */
    public function __construct(KmsClient $kms_client)
    {
        $this->kms_client = $kms_client;
    }

    public function generateKey($keyId, EncryptionContext $context = null)
    {

        $options = [
            'KeyId' => $keyId,
            'KeySpec' => 'AES_256'
        ];

        if ($context) {
            $array = $context->toArray();
            if (!empty($array)) {
                $options['EncryptionContext'] = $array;
            }
        }

        try {
            $response = $this->kms_client->generateDataKeyWithoutPlaintext($options);
        } catch (KmsException $e) {
            throw new GenerateException('Could not generate KMS key', 0, $e);
        }

        $key = new KeyDescription(base64_encode($response['CiphertextBlob']));
        if ($context) {
            $key->setEncryptionContext($context);
        }

        return $key;
    }
}
