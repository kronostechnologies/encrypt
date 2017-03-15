<?php

namespace Kronos\Encrypt;

class TextCrypt {
	/**
	 * @var Cypher\Adaptor
	 */
	private $cypher;

	/**
	 * @var KeyProvider\Adaptor
	 */
	private $provider;

	/**
	 * @param Cypher\Adaptor $cypher
	 * @param KeyProvider\Adaptor $provider
	 */
	public function __construct(Cypher\Adaptor $cypher, KeyProvider\Adaptor $provider) {
		$this->cypher = $cypher;
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

		return $this->cypher->encrypt($plaintext, $key);
	}

	/**
	 * @param $cyphertext
	 * @return string
	 */
	public function decrypt($cyphertext) {
		$key = $this->provider->getKey();

		return $this->cypher->decrypt($cyphertext, $key);
	}
}