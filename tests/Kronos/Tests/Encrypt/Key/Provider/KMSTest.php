<?php

namespace Kronos\Tests\Encrypt\Key\Provider;

use Aws\Command;
use Aws\Kms\KmsClient;
use Kronos\Encrypt\Key\Exception\FetchException;
use Kronos\Encrypt\Key\Provider\KMS;
use Kronos\Encrypt\Key\KMS\KeyDescription;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class KMSTest extends TestCase
{
    const CIPHERTEXT_BLOB = 'random binary string';
    const DECRYPTED_KEY = 'Decrypted key';
    const INVALID_BASE64 = '=InvalidBase64';

    const CONTEXT_ARRAY = [
        'key' => 'value'
    ];

    /**
     * @var MockObject
     */
    private $kms_client;

    /**
     * @var MockObject
     */
    private $key_description;

    /**
     * @var KMS
     */
    private $provider;

    public function setUp(): void
    {
        $this->kms_client = $this->createPartialMock(KmsClient::class, ['decrypt']);

        $this->key_description = $this->createMock(KeyDescription::class);

        $this->provider = new KMS($this->kms_client, $this->key_description);
    }

    public function test_getKey_ShouldGetCiphertextBlob(): void
    {
        $this->key_description
            ->expects(self::once())
            ->method('getCiphertextBlob')
            ->willReturn(base64_encode(self::CIPHERTEXT_BLOB));
        $this->kms_client->method('decrypt')->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

        $this->provider->getKey();
    }

    public function test_CiphertextBlob_getKey_ShouldGetContextAsArray(): void
    {
        $this->givenCiphertextBlob();
        $this->key_description
            ->expects(self::once())
            ->method('getEncryptionContextAsArray');
        $this->kms_client->method('decrypt')->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

        $this->provider->getKey();
    }

    public function test_DecodedCiphertextBlob_getKey_ShouldDecryptKey(): void
    {
        $this->givenCiphertextBlob();
        $this->kms_client
            ->expects(self::once())
            ->method('decrypt')
            ->with([
                'CiphertextBlob' => self::CIPHERTEXT_BLOB
            ])
            ->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

        $this->provider->getKey();
    }

    public function test_EncryptionContext_getKey_ShouldDecryptKeyWithContextArray(): void
    {
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
            ])
            ->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

        $this->provider->getKey();
    }

    public function test_DecryptedKey_getKey_ShouldReturnDecryptedKey(): void
    {
        $this->givenCiphertextBlob();
        $this->kms_client
            ->method('decrypt')
            ->willReturn(['Plaintext' => self::DECRYPTED_KEY]);

        $key = $this->provider->getKey();

        $this->assertEquals(self::DECRYPTED_KEY, $key);
    }

    public function test_AlreadyDecryptedKey_getKey_ShouldNotDecryptKeyTwiceAndReturnDecryptedKey(): void
    {
        $this->givenCiphertextBlob();
        $this->kms_client
            ->expects(self::once())
            ->method('decrypt')
            ->willReturn(['Plaintext' => self::DECRYPTED_KEY]);
        $this->provider->getKey();

        $key = $this->provider->getKey();

        $this->assertEquals(self::DECRYPTED_KEY, $key);
    }

    public function test_NonBase64EncodedCiphertextBlob_getKey_ShouldThrowException(): void
    {
        $this->givenInvalidBase64CiphertextBlob();
        $this->expectException(FetchException::class);

        $this->provider->getKey();
    }

    public function test_InvalidKey_getKey_ShouldThrowException(): void
    {
        $this->kms_client
            ->method('decrypt')
            ->will($this->throwException(new \Aws\Kms\Exception\KmsException('message', new Command('name'))));
        $this->expectException(FetchException::class);

        $this->provider->getKey();
    }

    private function givenCiphertextBlob(): void
    {
        $this->key_description
            ->method('getCiphertextBlob')
            ->willReturn(base64_encode(self::CIPHERTEXT_BLOB));
    }

    private function givenInvalidBase64CiphertextBlob(): void
    {
        $this->key_description
            ->method('getCiphertextBlob')
            ->willReturn(self::INVALID_BASE64);
    }

}
