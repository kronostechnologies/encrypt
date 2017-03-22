<?php

namespace Kronos\Encrypt\Key\KMS;

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