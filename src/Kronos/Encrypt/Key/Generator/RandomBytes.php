<?php

namespace Kronos\Encrypt\Key\Generator;


use Kronos\Encrypt\Key\Exception\GenerateException;

class RandomBytes
{
    public function generateKey()
    {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes(32));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $key = bin2hex(openssl_random_pseudo_bytes(32, $cryptoStrong));
            if (!$cryptoStrong) {
                throw new GenerateException('No cryptographically strong algorithm available.');
            }
            return $key;
        } else {
            throw new GenerateException('No cryptographically strong algorithm available.');
        }
    }
}
