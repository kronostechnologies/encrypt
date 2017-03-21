<?php

namespace Kronos\Tests\Encrypt\KeyProvider\KMS;


use Kronos\Encrypt\KeyProvider\KMS\EncryptionContext;
use Kronos\Encrypt\KeyProvider\KMS\KeyDescription;

class KeyDescriptionTest extends \PHPUnit_Framework_TestCase {
	const VALUE = 'value';
	const ANOTHER_VALUE = 'another value';
	const KEY_2 = 'key2';
	const KEY_1 = 'key1';
	const INVALID_VALUE = '';

	/**
	 * @var KeyDescription
	 */
	private $description;

	public function setUp() {
		$this->description = new KeyDescription();
	}

	public function test_buildContextFromArray_ShouldCreateContext() {
		$array = [
			self::KEY_1 => self::VALUE,
			self::KEY_2 => self::ANOTHER_VALUE
		];

		$this->description->buildContextFromArray($array);

		$this->assertCount(2, $this->description->context);
		$this->assertInstanceOf(EncryptionContext::class, $this->description->context[0]);
		$this->assertEquals(self::KEY_1, $this->description->context[0]->key);
		$this->assertEquals(self::VALUE, $this->description->context[0]->value);
		$this->assertInstanceOf(EncryptionContext::class, $this->description->context[1]);
		$this->assertEquals(self::KEY_2, $this->description->context[1]->key);
		$this->assertEquals(self::ANOTHER_VALUE, $this->description->context[1]->value);
	}

	public function test_ValidContext_getContextAsArray_ShouldReturnContextAsArray() {
		$this->description->context[] = $this->givenContext(self::KEY_1, self::VALUE);
		$this->description->context[] = $this->givenContext(self::KEY_2, self::ANOTHER_VALUE);

		$array = $this->description->getContextAsArray();

		$expected_array = [
			self::KEY_1 => self::VALUE,
			self::KEY_2 => self::ANOTHER_VALUE
		];
		$this->assertEquals($expected_array, $array);
	}

	public function test_TwoContextWithSameKey_getContextAsArray_ShouldReturnArrayWithSecondValue() {
		$this->description->context[] = $this->givenContext(self::KEY_1, self::VALUE);
		$this->description->context[] = $this->givenContext(self::KEY_1, self::ANOTHER_VALUE);

		$array = $this->description->getContextAsArray();

		$expected_array = [
			self::KEY_1 => self::ANOTHER_VALUE
		];
		$this->assertEquals($expected_array, $array);
	}

	public function test_InvalidContext_getContextAsArray_ShouldReturnEmptyArray() {
		$this->description->context[] = $this->givenContext(self::KEY_1, self::INVALID_VALUE);
		$this->description->context[] = $this->givenContext(self::KEY_2, self::ANOTHER_VALUE);

		$array = $this->description->getContextAsArray();

		$expected_array = [
			self::KEY_2 => self::ANOTHER_VALUE
		];
		$this->assertEquals($expected_array, $array);
	}


	private function givenContext($key, $value) {
		$context = new EncryptionContext();
		$context->key = $key;
		$context->value = $value;

		return $context;
	}
}