<?php

namespace Kronos\Tests\Encrypt\Key\Generator;

use Kronos\Encrypt\Key\Exception\GenerateException;
use Kronos\Encrypt\Key\Generator\KMS;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\KMS\EncryptionContext;
use Kronos\Encrypt\Key\KMS\KeyDescription;
use PHPUnit\Framework\TestCase;

class KMSTest extends TestCase {

	const KEY_ID = 'key id';
	const CIPHERTEXT_BLOB = 'binary string';
	const CONTEXT_ARRAY = [
		'field' => 'value'
	];

	/**
	 * @var KMS
	 */
	private $generator;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $kms_client;

	public function setUp(): void {
		$this->kms_client = $this->createPartialMock(KmsClient::class, ['generateDataKeyWithoutPlaintext']);

		$this->generator = new KMS($this->kms_client);
	}

	public function test_generateKey_ShouldGenerateDataKey() {
		$this->kms_client
			->expects(self::once())
			->method('generateDataKeyWithoutPlaintext')
			->with([
				'KeyId' => self::KEY_ID,
				'KeySpec' => 'AES_256'
			]);

		$this->generator->generateKey(self::KEY_ID);
	}

	public function test_generateKey_ShouldReturnKeyDescription() {
		$this->givenCiphertextBlob();

		$key = $this->generator->generateKey(self::KEY_ID);

		$this->assertInstanceOf(KeyDescription::class, $key);
		$this->assertEquals(base64_encode(self::CIPHERTEXT_BLOB), $key->getCiphertextBlob());
	}

	public function test_EncryptionContext_generateKey_ShouldGetAsArray() {
		$context = $this->createMock(EncryptionContext::class);
		$context
			->expects(self::once())
			->method('toArray');

		$this->generator->generateKey(self::KEY_ID, $context);
	}

	public function test_EncryptionContext_generateKey_ShouldGenerateKeyWithContextArray() {
		$context = $this->givenExcyptionContext();
		$this->kms_client
			->expects(self::once())
			->method('generateDataKeyWithoutPlaintext')
			->with([
				'KeyId' => self::KEY_ID,
				'KeySpec' => 'AES_256',
				'EncryptionContext' => self::CONTEXT_ARRAY
			]);

		$this->generator->generateKey(self::KEY_ID, $context);
	}

	public function test_EncryptionContext_generateKey_ShouldReturnKeyWithContext() {
		$context = $this->givenExcyptionContext();
		$this->givenCiphertextBlob();

		$key = $this->generator->generateKey(self::KEY_ID, $context);

		$this->assertInstanceOf(KeyDescription::class, $key);
		$this->assertSame($context, $key->getEncryptionContext());
	}

	public function test_EmptyEncryptionContextArray_generateKey_ShouldGenerateKeyWithoutEncryptionContext() {
		$context = $this->givenEmptyEncryptionContextArray();
		$this->kms_client
			->expects(self::once())
			->method('generateDataKeyWithoutPlaintext')
			->with([
				'KeyId' => self::KEY_ID,
				'KeySpec' => 'AES_256'
			]);

		$this->generator->generateKey(self::KEY_ID, $context);
	}

	public function test_KmsClientException_generateKey_ShouldThrowException() {
		$this->kms_client
			->method('generateDataKeyWithoutPlaintext')
			->will($this->throwException(new \Aws\Kms\Exception\KmsException('message', new \Aws\Command('name'))));
		$this->expectException(GenerateException::class);

		$this->generator->generateKey(self::KEY_ID);
	}

	private function givenCiphertextBlob() {
		$this->kms_client
			->method('generateDataKeyWithoutPlaintext')
			->willReturn([
				'CiphertextBlob' => self::CIPHERTEXT_BLOB
			]);
	}

	/**
	 * @return \PHPUnit_Framework_MockObject_MockObject
	 */
	private function givenExcyptionContext() {
		$context = $this->createMock(EncryptionContext::class);
		$context
			->method('toArray')
			->willReturn(self::CONTEXT_ARRAY);
		return $context;
	}

	/**
	 * @return \PHPUnit_Framework_MockObject_MockObject
	 */
	private function givenEmptyEncryptionContextArray() {
		$context = $this->createMock(EncryptionContext::class);
		$context
			->method('toArray')
			->willReturn([]);
		return $context;
	}
}
