<?php

namespace Kronos\Encrypt\KeyProvider;

interface Adaptor {

	/**
	 * Return encryption/decryption key
	 *
	 * @return string
	 */
	public function getKey();
}