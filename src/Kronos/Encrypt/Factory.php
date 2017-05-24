<?php

namespace Kronos\Encrypt;

use Aws\Kms\KmsClient;

class Factory {

	/**
	 * @return Cipher\AES
	 */
	public function createAESCipher() {
		return new Cipher\AES();
	}

	/**
	 * @return Cipher\None
	 */
	public function createPassthroughCipher() {
		return new Cipher\None();
	}

	/**
	 * @return Key\Generator\RandomBytes
	 */
	public function createRandomBytesGenerator() {
		return new Key\Generator\RandomBytes();
	}

	/**
	 * @param string $key
	 * @return Key\Provider\SimpleKey
	 */
	public function createSimpleKeyProvider($key) {
		return new Key\Provider\SimpleKey($key);
	}

	/**
	 * @param KmsClient $kmsClient
	 * @return Key\Generator\KMS
	 */
	public function createKMSKeyGenerator(KmsClient $kmsClient) {
		return new Key\Generator\KMS($kmsClient);
	}

	/**
	 * @param KmsClient $kmsClient
	 * @param string $ciphertextBlob
	 * @param array $context
	 * @return Key\Provider\KMS
	 */
	public function createKMSProvider(KmsClient $kmsClient, $ciphertextBlob, $context = []) {
		$keyDescription = new Key\KMS\KeyDescription($ciphertextBlob);
		if(count($context)) {
			$encryptionContext = new Key\KMS\EncryptionContext();
			foreach($context as $field => $value) {
				$encryptionContext->addField($field, $value);
			}
			$keyDescription->setEncryptionContext($encryptionContext);
		}
		return new Key\Provider\KMS($kmsClient, $keyDescription);
	}

	/**
	 * @param string $ciphertextBlob
	 * @return Key\KMS\KeyDescription
	 */
	public function createKMSKeyDescription($ciphertextBlob) {
		return new Key\KMS\KeyDescription($ciphertextBlob);
	}

	/**
	 * @return Key\KMS\EncryptionContext
	 */
	public function createKMSEncryptionContext() {
		return new Key\KMS\EncryptionContext();
	}
}