<?php

namespace Kronos\Encrypt\Key\Provider;

interface ProviderAdaptor
{

    /**
     * Return encryption/decryption key
     *
     * @return string
     */
    public function getKey(): string;
}
