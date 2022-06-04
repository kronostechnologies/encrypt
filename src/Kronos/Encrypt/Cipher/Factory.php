<?php

namespace Kronos\Encrypt\Cipher;

use phpseclib\Crypt\AES;

class Factory
{
    public function createCryptAES(int $mode = AES::MODE_CBC): AES
    {
        return new AES($mode);
    }
}
