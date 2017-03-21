<?php

namespace Kronos\Encrypt\KeyProvider\KMS;

class EncryptionContext {

	/**
	 * @var string
	 */
	public $key = '';

	/**
	 * @var string
	 */
	public $value = '';

	public function isValid() {
		return $this->key && $this->value;
	}
}