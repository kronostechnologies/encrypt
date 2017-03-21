<?php

namespace Kronos\Encrypt\KeyProvider\KMS;

class KeyDescription {

	/**
	 * CiphertextBlob returned by KMS GenerateDataKey
	 * @var string
	 */
	public $ciphertextBlob;

	/**
	 * Encryption context to send along the decryption of the ciphertextblob
	 * @var EncryptionContext[]
	 */
	public $context = [];

	/**
	 * @param $context array
	 */
	public function buildContextFromArray($context) {
		foreach($context as $key => $value) {
			$encryption_context = new EncryptionContext();
			$encryption_context->key = $key;
			$encryption_context->value = $value;

			$this->context[] = $encryption_context;
		}
	}

	public function getContextAsArray() {
		$array = [];

		foreach($this->context as $encryption_context) {
			if($encryption_context->isValid()) {
				$array[$encryption_context->key] = $encryption_context->value;
			}
		}

		return $array;
	}
}