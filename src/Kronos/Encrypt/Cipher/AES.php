<?php

namespace Kronos\Encrypt\Cipher;

use phpseclib\Crypt\AES as PHPSecAES;

class AES implements CipherAdaptor
{
    private Factory $factory;

    public function __construct(Factory $factory = null)
    {
        $this->factory = ($factory ?: new Factory());
    }

    /**
     * Use \phpseclib\Crypt\AES to encrypt plaintext using given key
     *
     * based on http://phpseclib.sourceforge.net/crypt/examples.html
     *
     * @param string $plaintext
     * @param string $key
     * @return string Ciphertext
     */
    public function encrypt(string $plaintext, string $key): string
    {
        $crypt_aes = $this->setupAES256($key);

        /** @psalm-suppress InternalMethod */
        return $crypt_aes->encrypt($plaintext);
    }

    public function decrypt(string $cyphertext, string $key): string
    {
        $crypt_aes = $this->setupAES256($key);

        /** @psalm-suppress InternalMethod */
        return $crypt_aes->decrypt($cyphertext);
    }

    private function setupAES256(string $key): PHPSecAES
    {
        $crypt_aes = $this->factory->createCryptAES();
        $crypt_aes->setKeyLength(256);
        $crypt_aes->setKey($key);

        return $crypt_aes;
    }

}
