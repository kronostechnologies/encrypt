<?php

namespace Kronos\Tests\Encrypt;

use Kronos\Encrypt\Encrypt;
use Kronos\Encrypt\Cipher\CipherAdaptor as Cipher;
use Kronos\Encrypt\Key\Provider\ProviderAdaptor as KeyProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class EncryptTest extends TestCase
{
    const PLAINTEXT = 'Plaintext string';
    const KEY = 'Cipher key';
    const CYPHERTEXT = 'Ciphertext';

    /**
     * @var Encrypt
     */
    private $encrypt;

    /**
     * @var MockObject
     */
    private $provider;

    /**
     * @var MockObject
     */
    private $cipher;

    public function setUp(): void
    {
        $this->cipher = $this->createMock(Cipher::class);
        $this->provider = $this->createMock(KeyProvider::class);

        $this->encrypt = new Encrypt($this->cipher, $this->provider);
    }

    // encrypt

    public function test_encrypt_ShouldGetCipherKey(): void
    {
        $this->provider
            ->expects(self::once())
            ->method('getKey');

        $this->encrypt->encrypt(self::PLAINTEXT);
    }

    public function test_Key_encrypt_ShouldEncryptPlaintextWithKey(): void
    {
        $this->givenKey();
        $this->cipher
            ->expects(self::once())
            ->method('encrypt')
            ->with(self::PLAINTEXT, self::KEY);

        $this->encrypt->encrypt(self::PLAINTEXT);
    }

    public function test_EncryptedPlaintext_encrypt_ShouldReturnCiphertext(): void
    {
        $this->givenKey();
        $this->givenCipherEncryptedPlaintext();

        $cyphertext = $this->encrypt->encrypt(self::PLAINTEXT);

        $this->assertEquals(self::CYPHERTEXT, $cyphertext);
    }

    // decrypt

    public function test_decrypt_ShouldGetCipherKey(): void
    {
        $this->provider
            ->expects(self::once())
            ->method('getKey');

        $this->encrypt->decrypt(self::PLAINTEXT);
    }

    public function test_Key_decrypt_ShouldDecryptCipherWithKey(): void
    {
        $this->givenKey();
        $this->cipher
            ->expects(self::once())
            ->method('decrypt')
            ->with(self::CYPHERTEXT, self::KEY);

        $this->encrypt->decrypt(self::CYPHERTEXT);
    }

    public function test_DecryptedCiphertext_decrypt_ShouldReturnPlaintext(): void
    {
        $this->givenKey();
        $this->givenCipherDecryptedCiphertext();

        $cyphertext = $this->encrypt->decrypt(self::CYPHERTEXT);

        $this->assertEquals(self::PLAINTEXT, $cyphertext);
    }

    // utility functions

    private function givenKey(): void
    {
        $this->provider
            ->method('getKey')
            ->willReturn(self::KEY);
    }

    private function givenCipherEncryptedPlaintext(): void
    {
        $this->cipher
            ->method('encrypt')
            ->willReturn(self::CYPHERTEXT);
    }

    private function givenCipherDecryptedCiphertext(): void
    {
        $this->cipher
            ->method('decrypt')
            ->willReturn(self::PLAINTEXT);
    }
}
