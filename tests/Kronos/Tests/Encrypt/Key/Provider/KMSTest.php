<?php

namespace Kronos\Tests\Encrypt\Key\Provider;

use Aws\Command;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\Exception\FetchException;
use Kronos\Encrypt\Key\Provider\KMS;
use Kronos\Encrypt\Key\KMS\KeyDescription;

class KMSTest extends \PHPUnit_Framework_TestCase {
	const CIPHERTEXT_BLOB = 'base64 data object';
	const DECRYPTED_KEY = 'Decrypted key';

	const CONTEXT_ARRAY = [
		'key' => 'value'
	];

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $kms_client;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $key_description;

	/**
	 * @var KMS
	 */
	private $provider;

	public function setUp() {
		$this->kms_client = $this->createPartialMock(KmsClient::class, ['decrypt']);

		$this->key_description = $this->createMock(KeyDescription::class);

		$this->provider = new KMS($this->kms_client, $this->key_description);
	}

	public function test_getKey_ShouldGetCiphertextBlob() {
		$this->key_description
			->expects(self::once())
			->method('getCiphertextBlob');

		$this->provider->getKey();
	}

	public function test_getKey_ShouldGetContextAsArray() {
		$this->key_description
			->expects(self::once())
			->method('getEncryptionContextAsArray');

		$this->provider->getKey();
	}

	public function test_DecodedCiphertextBlob_getKey_ShouldDecryptKey() {
		$this->givenCiphertextBlob();
		$this->kms_client
			->expects(self::once())
			->method('decrypt')
			->with([
				'CiphertextBlob' => self::CIPHERTEXT_BLOB
			]);

		$this->provider->getKey();
	}

	public function test_EncryptionContext_getKey_ShouldDecryptKeyWithContextArray() {
		$this->givenCiphertextBlob();
		$this->key_description
			->method('getEncryptionContextAsArray')
			->willReturn(self::CONTEXT_ARRAY);
		$this->kms_client
			->expects(self::once())
			->method('decrypt')
			->with([
				'CiphertextBlob' => self::CIPHERTEXT_BLOB,
				'EncryptionContext' => self::CONTEXT_ARRAY
			]);

		$this->provider->getKey();
	}

	public function test_DecryptedKey_getKey_ShouldReturnDecryptedKey() {
		$this->givenCiphertextBlob();
		$this->kms_client
			->method('decrypt')
			->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

		$key = $this->provider->getKey();

		$this->assertEquals(self::DECRYPTED_KEY, $key);
	}

	public function test_AlreadyDecryptedKey_getKey_ShouldNotDecryptKeyTwiceAndReturnDecryptedKey() {
		$this->kms_client
			->expects(self::once())
			->method('decrypt')
			->willReturn(['Plaintext' => self::DECRYPTED_KEY]);
		$this->provider->getKey();

		$key = $this->provider->getKey();

		$this->assertEquals(self::DECRYPTED_KEY, $key);
	}

	public function test_InvalidKey_getKey_ShouldThrowException() {
		$this->kms_client
			->method('decrypt')
			->will($this->throwException(new \Aws\Kms\Exception\KmsException('message', new Command('name'))));
		$this->expectException(FetchException::class);

		$this->provider->getKey();
	}

	private function givenCiphertextBlob() {
		$this->key_description
			->method('getCiphertextBlob')
			->willReturn(self::CIPHERTEXT_BLOB);
	}
}