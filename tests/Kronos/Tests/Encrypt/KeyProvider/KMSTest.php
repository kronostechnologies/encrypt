<?php

namespace Kronos\Tests\Encrypt\KeyProvider;

use Aws\Kms\KmsClient;
use Kronos\Encrypt\KeyProvider\KMS;
use Kronos\Encrypt\KeyProvider\KMS\KeyDescription;

class KMSTest extends \PHPUnit_Framework_TestCase {
	const CIPHERTEXT_BLOB = 'base64 data object';
	const DECRYPTED_KEY = 'Decrypted key';

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $kms_client;

	/**
	 * @var KeyDescription
	 */
	private $key_description;

	/**
	 * @var KMS
	 */
	private $provider;

	public function setUp() {
		$this->kms_client = $this->createPartialMock(KmsClient::class, ['decrypt']);

		$this->key_description = new KeyDescription();
		$this->key_description->ciphertextBlob = self::CIPHERTEXT_BLOB;
		$this->key_description->context = ['somecontext' => 'value'];

		$this->provider = new KMS($this->kms_client, $this->key_description);
	}

	public function test_getKey_ShouldDecryptKey() {
		$this->kms_client
			->expects(self::once())
			->method('decrypt')
			->with([
				'CiphertextBlob' => $this->key_description->ciphertextBlob,
				//'EncryptionContext' => $this->key_description->context
			]);

		$this->provider->getKey();
	}

	public function test_DecryptedKey_getKey_ShouldReturnDecryptedKey() {
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
}