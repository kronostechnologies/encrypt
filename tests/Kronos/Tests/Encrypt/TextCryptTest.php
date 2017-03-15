<?php

namespace Kronos\Tests\Encrypt;

use \Kronos\Encrypt\TextCrypt,
	\Kronos\Encrypt\Cypher\Adaptor as Cypher,
	\Kronos\Encrypt\KeyProvider\Adaptor as KeyProvider;

class TextCryptTest extends \PHPUnit_Framework_TestCase {
	const PLAINTEXT_STRING = 'Plaintext string';

	/**
	 * @var TextCrypt
	 */
	private $textcrypt;

	/**
	 * @var \PHPUnit_Framework_MockObject_MockObject
	 */
	private $provider;

	/**
	 * @var \PHPUnit_Framework_MockObject_MockObject
	 */
	private $cypher;

	public function setUp() {
		$this->cypher = $this->createMock(Cypher::class);
		$this->provider = $this->createMock(KeyProvider::class);

		$this->textcrypt = new TextCrypt($this->cypher, $this->provider);
	}

	public function test_encrypt_ShouldGetCypherKey() {
		$this->provider
			->expects(self::once())
			->method('getKey');

		$this->textcrypt->encrypt(self::PLAINTEXT_STRING);
	}
}