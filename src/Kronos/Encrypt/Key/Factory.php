<?php

namespace Kronos\Encrypt\Key;

use Aws\Kms\KmsClient;

class Factory {

	/**
	 * @param KmsClient $kmsClient
	 * @param string $ciphertextBlob
	 * @param array $context
	 * @return Provider\KMS
	 */
	public function createKMSProvider(KmsClient $kmsClient, $ciphertextBlob, $context = []) {
		$keyDescription = new KMS\KeyDescription($ciphertextBlob);
		if(count($context)) {
			$encryptionContext = new KMS\EncryptionContext();
			foreach($context as $field => $value) {
				$encryptionContext->addField($field, $value);
			}
			$keyDescription->setEncryptionContext($encryptionContext);
		}
		return new Provider\KMS($kmsClient, $keyDescription);
	}
}