<?php

namespace Kronos\Tests\Encrypt\Cipher;

use Kronos\Encrypt\Cipher\AES;
use Kronos\Encrypt\Cipher\Factory;
use PHPUnit\Framework\TestCase;

class AESTest extends TestCase {
	const PLAINTEXT = 'Plaintext';
	const KEY = 'Key';
	const CIPHERTEXT = 'Ciphertext';

	/**
	 * @var \PHPUnit_Framework_MockObject_MockObject
	 */
	private $factory;

	/**
	 * @var \PHPUnit_Framework_MockObject_MockObject
	 */
	private $crypt_aes;

	/**
	 * @var AES
	 */
	private $aes_adaptor;

	public function setUp(): void {
		$this->crypt_aes = $this->createMock(\phpseclib\Crypt\AES::class);
		$this->factory = $this->createMock(Factory::class);
		$this->factory
			->method('createCryptAES')
			->willReturn($this->crypt_aes);

		$this->aes_adaptor = new AES($this->factory);
	}

	// encrypt

	public function test_encrypt_ShouldCreateCryptAES() {
		$this->factory
			->expects(self::once())
			->method('createCryptAES');

		$this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
	}

	public function test_CryptAES_encrypt_ShouldSetKeyLengthTo256() {
		$this->crypt_aes
			->expects(self::once())
			->method('setKeyLength')
			->with(256);

		$this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
	}

	public function test_CryptAES_encrypt_ShouldSetKey() {
		$this->crypt_aes
			->expects(self::once())
			->method('setKey')
			->with(self::KEY);

		$this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
	}

	public function test_CryptAES_encrypt_ShouldEncryptPlaintext() {
		$this->crypt_aes
			->expects(self::once())
			->method('encrypt')
			->with(self::PLAINTEXT);

		$this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
	}

	public function test_CryptAES_encrypt_ShouldReturnCiphertext() {
		$this->crypt_aes
			->method('encrypt')
			->willReturn(self::CIPHERTEXT);

		$Ciphertext = $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);

		$this->assertEquals(self::CIPHERTEXT, $Ciphertext);
	}

	// decrypt

	public function test_decrypt_ShouldCreateCryptAES() {
		$this->factory
			->expects(self::once())
			->method('createCryptAES');

		$this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
	}

	public function test_CryptAES_decrypt_ShouldSetKeyLengthTo256() {
		$this->crypt_aes
			->expects(self::once())
			->method('setKeyLength')
			->with(256);

		$this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
	}

	public function test_CryptAES_decrypt_ShouldSetKey() {
		$this->crypt_aes
			->expects(self::once())
			->method('setKey')
			->with(self::KEY);

		$this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
	}

	public function test_CryptAES_decrypt_ShouldEncryptPlaintext() {
		$this->crypt_aes
			->expects(self::once())
			->method('decrypt')
			->with(self::CIPHERTEXT);

		$this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
	}

	public function test_CryptAES_decrypt_ShouldReturnCiphertext() {
		$this->crypt_aes
			->method('decrypt')
			->willReturn(self::PLAINTEXT);

		$Ciphertext = $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);

		$this->assertEquals(self::PLAINTEXT, $Ciphertext);
	}
}
