<?php

namespace Kronos\Encrypt\Key;

use Aws\Kms\KmsClient;

class Factory {

	/**
	 * @return Generator\RandomBytes
	 */
	public function createRandomBytesGenerator() {
		return new Generator\RandomBytes();
	}

	/**
	 * @param string $key
	 * @return Provider\SimpleKey
	 */
	public function createSimpleKeyProvider($key) {
		return new Provider\SimpleKey($key);
	}

	/**
	 * @param KmsClient $kmsClient
	 * @return Generator\KMS
	 */
	public function createKMSKeyGenerator(KmsClient $kmsClient) {
		return new Generator\KMS($kmsClient);
	}

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

	/**
	 * @param string $ciphertextBlob
	 * @return KMS\KeyDescription
	 */
	public function createKMSKeyDescription($ciphertextBlob) {
		return new KMS\KeyDescription($ciphertextBlob);
	}

	/**
	 * @return KMS\EncryptionContext
	 */
	public function createEncryptionContext() {
		return new KMS\EncryptionContext();
	}
}