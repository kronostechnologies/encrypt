<?php

namespace Kronos\Encrypt\Cipher;

class None implements Adaptor
{
    public function encrypt($plaintext, $key)
    {
        return $plaintext;
    }

    public function decrypt($cyphertext, $key)
    {
        return $cyphertext;
    }
}
