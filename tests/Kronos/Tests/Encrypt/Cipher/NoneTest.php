<?php

namespace Kronos\Tests\Encrypt\Cipher;

use Kronos\Encrypt\Cipher\None;

class NoneTest extends \PHPUnit_Framework_TestCase {

	const PLAINTEXT = 'plaintext';
	const CIPHERTEXT = 'ciphertext';
	const KEY = 'key';

	/**
	 * @var None
	 */
	private $cipher;

	public function setUp() {
		$this->cipher = new None();
	}

	public function test_encrypt_ShouldReturnPlainbtext() {
		$plaintext = self::PLAINTEXT;

		$ciphertext = $this->cipher->encrypt($plaintext, self::KEY);

		$this->assertEquals($plaintext, $ciphertext);
	}

	public function test_decrypt_ShouldReturnCiphertext() {
		$ciphertext = self::CIPHERTEXT;

		$plaintext= $this->cipher->decrypt($ciphertext, self::KEY);

		$this->assertEquals($ciphertext, $plaintext);
	}
}