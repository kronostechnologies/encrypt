<?php

namespace Kronos\Tests\Encrypt\Key\KMS;


use Kronos\Encrypt\Key\KMS\EncryptionContext;
use Kronos\Encrypt\Key\KMS\KeyDescription;
use PHPUnit\Framework\TestCase;

class KeyDescriptionTest extends TestCase {
	const VALUE = 'value';
	const FIELD = 'field';

	/**
	 * @var KeyDescription
	 */
	private $description;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $context;

	public function setUp(): void {
		$this->description = new KeyDescription('ciphertextBlob');

		$this->context = $this->createMock(EncryptionContext::class);
	}

	public function test_EncryptionContext_getEncryptionContextAsArray_ShouldGetEncryptionContextArray() {
		$this->description->setEncryptionContext($this->context);
		$this->context
			->expects(self::once())
			->method('toArray');

		$this->description->getEncryptionContextAsArray();
	}

	public function test_EncryptionContext_getEncryptionContextAsArray_ShouldReturnArray() {
		$expected_array = [self::FIELD => self::VALUE];
		$this->description->setEncryptionContext($this->context);
		$this->context
			->method('toArray')
			->willReturn($expected_array);

		$actual_array = $this->description->getEncryptionContextAsArray();

		$this->assertSame($expected_array, $actual_array);
	}

	public function test_NoEncryptionContext_getEncryptionContextAsArray_ShouldReturnEmptyArray() {
		$actual_array = $this->description->getEncryptionContextAsArray();

		$this->assertSame([], $actual_array);
	}
}
