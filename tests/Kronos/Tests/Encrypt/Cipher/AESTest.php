<?php

namespace Kronos\Tests\Encrypt\Cipher;

use Kronos\Encrypt\Cipher\AES;
use Kronos\Encrypt\Cipher\Factory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use phpseclib\Crypt\AES as PHPSecAES;

class AESTest extends TestCase
{
    const PLAINTEXT = 'Plaintext';
    const KEY = 'Key';
    const CIPHERTEXT = 'Ciphertext';

    /**
     * @var MockObject
     */
    private $factory;

    /**
     * @var MockObject
     */
    private $crypt_aes;

    /**
     * @var AES
     */
    private $aes_adaptor;

    public function setUp(): void
    {
        $this->crypt_aes = $this->createMock(PHPSecAES::class);
        $this->factory = $this->createMock(Factory::class);
        $this->factory
            ->method('createCryptAES')
            ->willReturn($this->crypt_aes);

        $this->aes_adaptor = new AES($this->factory);
    }

    // encrypt

    public function test_encrypt_ShouldCreateCryptAES(): void
    {
        $this->factory
            ->expects(self::once())
            ->method('createCryptAES');
        $this->crypt_aes->method('encrypt')->willReturn("");

        $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
    }

    public function test_CryptAES_encrypt_ShouldSetKeyLengthTo256(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('setKeyLength')
            ->with(256);
        $this->crypt_aes->method('encrypt')->willReturn("");

        $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
    }

    public function test_CryptAES_encrypt_ShouldSetKey(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('setKey')
            ->with(self::KEY);
        $this->crypt_aes->method('encrypt')->willReturn("");

        $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
    }

    public function test_CryptAES_encrypt_ShouldEncryptPlaintext(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('encrypt')
            ->with(self::PLAINTEXT)
            ->willReturn(self::CIPHERTEXT);

        $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);
    }

    public function test_CryptAES_encrypt_ShouldReturnCiphertext(): void
    {
        $this->crypt_aes
            ->method('encrypt')
            ->willReturn(self::CIPHERTEXT);

        $Ciphertext = $this->aes_adaptor->encrypt(self::PLAINTEXT, self::KEY);

        $this->assertEquals(self::CIPHERTEXT, $Ciphertext);
    }

    // decrypt

    public function test_decrypt_ShouldCreateCryptAES(): void
    {
        $this->factory
            ->expects(self::once())
            ->method('createCryptAES');
        $this->crypt_aes->method('decrypt')->willReturn("");

        $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
    }

    public function test_CryptAES_decrypt_ShouldSetKeyLengthTo256(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('setKeyLength')
            ->with(256);
        $this->crypt_aes->method('decrypt')->willReturn("");

        $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
    }

    public function test_CryptAES_decrypt_ShouldSetKey(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('setKey')
            ->with(self::KEY);
        $this->crypt_aes->method('decrypt')->willReturn("");

        $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
    }

    public function test_CryptAES_decrypt_ShouldEncryptPlaintext(): void
    {
        $this->crypt_aes
            ->expects(self::once())
            ->method('decrypt')
            ->with(self::CIPHERTEXT)
            ->willReturn(self::PLAINTEXT);

        $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);
    }

    public function test_CryptAES_decrypt_ShouldReturnCiphertext(): void
    {
        $this->crypt_aes
            ->method('decrypt')
            ->willReturn(self::PLAINTEXT);

        $Ciphertext = $this->aes_adaptor->decrypt(self::CIPHERTEXT, self::KEY);

        $this->assertEquals(self::PLAINTEXT, $Ciphertext);
    }
}
