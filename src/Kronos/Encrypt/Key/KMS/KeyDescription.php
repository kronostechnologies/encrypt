<?php

namespace Kronos\Encrypt\Key\KMS;

class KeyDescription {

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
	public function __construct($ciphertextBlob) {
		$this->ciphertextBlob = $ciphertextBlob;
	}

	/**
	 * @param EncryptionContext $context
	 */
	public function setEncryptionContext($context) {
		$this->context = $context;
	}

	/**
	 * @return string
	 */
	public function getCiphertextBlob() {
		return $this->ciphertextBlob;
	}

	/**
	 * @return EncryptionContext
	 */
	public function getEncryptionContext() {
		return $this->context;
	}

	/**
	 * Return encryption context as an array
	 * @return array
	 */
	public function getEncryptionContextAsArray() {
		if($this->context) {
			return $this->context->toArray();
		}
		else {
			return [];
		}
	}
}