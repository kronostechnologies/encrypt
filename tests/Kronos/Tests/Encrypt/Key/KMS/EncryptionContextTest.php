<?php

namespace Kronos\Tests\Encrypt\Key\KMS;

use Kronos\Encrypt\Key\KMS\EncryptionContext;

class EncryptionContextTest extends \PHPUnit_Framework_TestCase {
	const FIELD = 'field';
	const EMTPY_FIELD = '';
	const VALUE = 'value';
	const ANOTHER_VALUE = 'other value';

	/**
	 * @var EncryptionContext
	 */
	private $context;

	public function setUp() {
		$this->context = new EncryptionContext();
	}

	public function test_AddedContext_toArray_ShouldReturnArrayContainingAddedContext() {
		$this->context->addField(self::FIELD, self::VALUE);

		$array = $this->context->toArray();

		$this->assertEquals([self::FIELD => self::VALUE], $array);
	}

	public function test_AddedContextWithEmptyField_toArray_ShouldReturnArrayExcludingEmptyField() {
		$this->context->addField(self::FIELD, self::VALUE);
		$this->context->addField(self::EMTPY_FIELD, self::VALUE);

		$array = $this->context->toArray();

		$this->assertEquals([self::FIELD => self::VALUE], $array);
	}

	public function test_AddingTwiceTheSameField_toArray_ShouldReturnArrayWithLastGivenFieldValue() {
		$this->context->addField(self::FIELD, self::VALUE);
		$this->context->addField(self::FIELD, self::ANOTHER_VALUE);

		$array = $this->context->toArray();

		$this->assertEquals([self::FIELD => self::ANOTHER_VALUE], $array);
	}
}