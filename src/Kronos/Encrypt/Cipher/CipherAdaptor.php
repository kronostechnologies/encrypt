<?php

namespace Kronos\Encrypt\Cipher;

interface CipherAdaptor
{
    /**
     * @param string $plaintext Plaintext to encrypt
     * @param string $key Key used to encrypt
     * @return string Cyphertext
     */
    public function encrypt(string $plaintext, string $key): string;

    /**
     * @param string $cyphertext Cyphertext to decrypt
     * @param string $key Key used to decrypt
     * @return string Plaintext
     */
    public function decrypt(string $cyphertext, string $key): string;
}
