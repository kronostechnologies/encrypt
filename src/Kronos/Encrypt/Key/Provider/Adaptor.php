<?php

namespace Kronos\Encrypt\Key\Provider;

interface Adaptor
{

    /**
     * Return encryption/decryption key
     *
     * @return string
     */
    public function getKey();
}
