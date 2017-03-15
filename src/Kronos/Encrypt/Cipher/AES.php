<?php

namespace Kronos\Encrypt\Cipher;

class AES implements Adaptor {

	/**
	 * @var Factory
	 */
	private $factory;

	public function __construct($factory = NULL) {
		$this->factory = ($factory ?: new Factory());
	}

	/**
	 * Use \phpseclib\Crypt\AES to encrypt plaintext using given key
	 *
	 * based on http://phpseclib.sourceforge.net/crypt/examples.html
	 *
	 * @param string $plaintext
	 * @param string $key
	 * @return string Ciphertext
	 */
	public function encrypt($plaintext, $key) {
		$crypt_aes = $this->setupAES256($key);

		return $crypt_aes->encrypt($plaintext);
	}

	public function decrypt($cyphertext, $key) {
		$crypt_aes = $this->setupAES256($key);

		return $crypt_aes->decrypt($cyphertext);
	}

	/**
	 * @param $key
	 * @return \phpseclib\Crypt\AES
	 */
	private function setupAES256($key) {
		$crypt_aes = $this->factory->createCryptAES();
		$crypt_aes->setKeyLength(256);
		$crypt_aes->setKey($key);

		return $crypt_aes;
	}

}