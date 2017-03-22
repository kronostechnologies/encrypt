<?php

namespace Kronos\Encrypt;

class TextCrypt {
	/**
	 * @var Cipher\Adaptor
	 */
	private $cipher;

	/**
	 * @var Key\Provider\Adaptor
	 */
	private $provider;

	/**
	 * @param Cipher\Adaptor $cipher
	 * @param Key\Provider\Adaptor $provider
	 */
	public function __construct(Cipher\Adaptor $cipher, Key\Provider\Adaptor $provider) {
		$this->cipher = $cipher;
		$this->provider = $provider;
	}

	/**
	 * Encrypt plaintext using given cypher and provided key
	 *
	 * @param $plaintext
	 * @return string
	 */
	public function encrypt($plaintext) {
		$key = $this->provider->getKey();

		return $this->cipher->encrypt($plaintext, $key);
	}

	/**
	 * @param $cyphertext
	 * @return string
	 */
	public function decrypt($cyphertext) {
		$key = $this->provider->getKey();

		return $this->cipher->decrypt($cyphertext, $key);
	}
}