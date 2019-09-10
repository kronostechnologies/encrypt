<?php

namespace Kronos\Tests\Encrypt\Cipher;

use Kronos\Encrypt\Cipher\None;
use PHPUnit\Framework\TestCase;

class NoneTest extends TestCase
{

    const PLAINTEXT = 'plaintext';
    const CIPHERTEXT = 'ciphertext';
    const KEY = 'key';

    /**
     * @var None
     */
    private $cipher;

    public function setUp(): void
    {
        $this->cipher = new None();
    }

    public function test_encrypt_ShouldReturnPlainbtext()
    {
        $plaintext = self::PLAINTEXT;

        $ciphertext = $this->cipher->encrypt($plaintext, self::KEY);

        $this->assertEquals($plaintext, $ciphertext);
    }

    public function test_decrypt_ShouldReturnCiphertext()
    {
        $ciphertext = self::CIPHERTEXT;

        $plaintext = $this->cipher->decrypt($ciphertext, self::KEY);

        $this->assertEquals($ciphertext, $plaintext);
    }
}
