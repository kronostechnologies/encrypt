<?php

namespace Kronos\Tests\Encrypt;

use \Kronos\Encrypt\TextCrypt,
	\Kronos\Encrypt\Cipher\Adaptor as Cipher,
	\Kronos\Encrypt\Key\Provider\Adaptor as KeyProvider;

class TextCryptTest extends \PHPUnit_Framework_TestCase {
	const PLAINTEXT = 'Plaintext string';
	const KEY = 'Cipher key';
	const CYPHERTEXT = 'Ciphertext';

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
	private $cipher;

	public function setUp() {
		$this->cipher = $this->createMock(Cipher::class);
		$this->provider = $this->createMock(KeyProvider::class);

		$this->textcrypt = new TextCrypt($this->cipher, $this->provider);
	}

	// encrypt

	public function test_encrypt_ShouldGetCipherKey() {
		$this->provider
			->expects(self::once())
			->method('getKey');

		$this->textcrypt->encrypt(self::PLAINTEXT);
	}

	public function test_Key_encrypt_ShouldEncryptPlaintextWithKey() {
		$this->givenKey();
		$this->cipher
			->expects(self::once())
			->method('encrypt')
			->with(self::PLAINTEXT, self::KEY);

		$this->textcrypt->encrypt(self::PLAINTEXT);
	}

	public function test_EncryptedPlaintext_encrypt_ShouldReturnCiphertext() {
		$this->givenKey();
		$this->givenCipherEncryptedPlaintext();

		$cyphertext = $this->textcrypt->encrypt(self::PLAINTEXT);

		$this->assertEquals(self::CYPHERTEXT, $cyphertext);
	}

	// decrypt

	public function test_decrypt_ShouldGetCipherKey() {
		$this->provider
			->expects(self::once())
			->method('getKey');

		$this->textcrypt->decrypt(self::PLAINTEXT);
	}

	public function test_Key_decrypt_ShouldDecryptCipherWithKey() {
		$this->givenKey();
		$this->cipher
			->expects(self::once())
			->method('decrypt')
			->with(self::CYPHERTEXT, self::KEY);

		$this->textcrypt->decrypt(self::CYPHERTEXT);
	}

	public function test_DecryptedCiphertext_decrypt_ShouldReturnPlaintext() {
		$this->givenKey();
		$this->givenCipherDecryptedCiphertext();

		$cyphertext = $this->textcrypt->decrypt(self::CYPHERTEXT);

		$this->assertEquals(self::PLAINTEXT, $cyphertext);
	}

	// utility functions

	private function givenKey() {
		$this->provider
			->method('getKey')
			->willReturn(self::KEY);
	}

	private function givenCipherEncryptedPlaintext() {
		$this->cipher
			->method('encrypt')
			->willReturn(self::CYPHERTEXT);
	}

	private function givenCipherDecryptedCiphertext() {
		$this->cipher
			->method('decrypt')
			->willReturn(self::PLAINTEXT);
	}
}