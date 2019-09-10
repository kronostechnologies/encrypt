<?php

namespace Kronos\Encrypt\Cipher;

class Factory
{

    /**
     * @param int $mode AES mode, default CBC
     * @return \phpseclib\Crypt\AES
     */
    public function createCryptAES($mode = \phpseclib\Crypt\AES::MODE_CBC): \phpseclib\Crypt\AES
    {
        return new \phpseclib\Crypt\AES($mode);
    }
}
