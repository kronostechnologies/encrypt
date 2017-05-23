<?php

namespace Kronos\Encrypt\Key\Provider;

class SimpleKey implements Adaptor {

	/**
	 * @var string
	 */
	private $key;

	/**
	 * StringKey constructor.
	 * @param string $key Key to hold and give back
	 */
	public function __construct($key) {
		$this->key = $key;
	}


	public function getKey() {
		return $this->key;
	}

}