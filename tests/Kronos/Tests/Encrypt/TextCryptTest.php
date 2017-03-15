<?php

namespace Kronos\Tests\Encrypt;

use \Kronos\Encrypt\TextCrypt,
	\Kronos\Encrypt\Cypher\Adaptor as Cypher,
	\Kronos\Encrypt\KeyProvider\Adaptor as KeyProvider;

class TextCryptTest extends \PHPUnit_Framework_TestCase {
	const PLAINTEXT = 'Plaintext string';
	const KEY = 'Cypher key';
	const CYPHERTEXT = 'Cyphertext';

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

	// encrypt

	public function test_encrypt_ShouldGetCypherKey() {
		$this->provider
			->expects(self::once())
			->method('getKey');

		$this->textcrypt->encrypt(self::PLAINTEXT);
	}

	public function test_Key_encrypt_ShouldEncryptPlaintextWithKey() {
		$this->givenKey();
		$this->cypher
			->expects(self::once())
			->method('encrypt')
			->with(self::PLAINTEXT, self::KEY);

		$this->textcrypt->encrypt(self::PLAINTEXT);
	}

	public function test_EncryptedPlaintext_encrypt_ShouldReturnCyphertext() {
		$this->givenKey();
		$this->givenCypherEncryptedPlaintext();

		$cyphertext = $this->textcrypt->encrypt(self::PLAINTEXT);

		$this->assertEquals(self::CYPHERTEXT, $cyphertext);
	}

	// decrypt

	public function test_decrypt_ShouldGetCypherKey() {
		$this->provider
			->expects(self::once())
			->method('getKey');

		$this->textcrypt->decrypt(self::PLAINTEXT);
	}

	public function test_Key_decrypt_ShouldDecryptCypherWithKey() {
		$this->givenKey();
		$this->cypher
			->expects(self::once())
			->method('decrypt')
			->with(self::CYPHERTEXT, self::KEY);

		$this->textcrypt->decrypt(self::CYPHERTEXT);
	}

	public function test_DecryptedCyphertext_decrypt_ShouldReturnPlaintext() {
		$this->givenKey();
		$this->givenCypherDecryptedCyphertext();

		$cyphertext = $this->textcrypt->decrypt(self::CYPHERTEXT);

		$this->assertEquals(self::PLAINTEXT, $cyphertext);
	}

	// utility functions

	private function givenKey() {
		$this->provider
			->method('getKey')
			->willReturn(self::KEY);
	}

	private function givenCypherEncryptedPlaintext() {
		$this->cypher
			->method('encrypt')
			->willReturn(self::CYPHERTEXT);
	}

	private function givenCypherDecryptedCyphertext() {
		$this->cypher
			->method('decrypt')
			->willReturn(self::PLAINTEXT);
	}
}