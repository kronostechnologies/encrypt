<?php

namespace Kronos\Encrypt\Cipher;

class None implements CipherAdaptor
{
    /**
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    public function encrypt(string $plaintext, string $key): string
    {
        return $plaintext;
    }

    /**
     * @param string $cyphertext
     * @param string $key
     * @return string
     */
    public function decrypt(string $cyphertext, string $key): string
    {
        return $cyphertext;
    }
}
