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
	 * @param $text
	 */
	public function encrypt($text) {
		$this->provider->getKey();
	}
}