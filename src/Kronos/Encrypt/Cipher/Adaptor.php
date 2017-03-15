<?php

namespace Kronos\Encrypt\Cipher;

interface Adaptor {

	/**
	 * @param $plaintext string Plaintext to encrypt
	 * @param $key string Key used to encrypt
	 * @return string Cyphertext
	 */
	public function encrypt($plaintext, $key);

	/**
	 * @param $cyphertext string Cyphertext to decrypt
	 * @param $key string Key used to decrypt
	 * @return string Plaintext
	 */
	public function decrypt($cyphertext, $key);
}