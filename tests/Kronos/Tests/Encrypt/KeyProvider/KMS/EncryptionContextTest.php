<?php

namespace Kronos\Tests\Encrypt\KeyProvider\KMS;

use Kronos\Encrypt\KeyProvider\KMS\EncryptionContext;

class EncryptionContextTest extends \PHPUnit_Framework_TestCase {
	const KEY = 'key';
	const VALUE = 'value';

	/**
	 * @var EncryptionContext
	 */
	private $context;

	public function setUp() {
		$this->context = new EncryptionContext();
	}

	public function test_KeyAndValue_isValid_ShouldReturnTrue() {
		$this->context->key = self::KEY;
		$this->context->value = self::VALUE;

		$valid = $this->context->isValid();

		$this->assertTrue($valid);
	}

	public function test_OnlyKey_isValid_ShouldReturnFalse() {
		$this->context->key = self::KEY;

		$valid = $this->context->isValid();

		$this->assertFalse($valid);
	}

	public function test_OnlyValue_isValid_ShouldReturnFalse() {
		$this->context->value = self::VALUE;

		$valid = $this->context->isValid();

		$this->assertFalse($valid);
	}

	public function test_NoKeyOrValue_isValid_ShouldReturnFalse() {
		$valid = $this->context->isValid();

		$this->assertFalse($valid);
	}
}