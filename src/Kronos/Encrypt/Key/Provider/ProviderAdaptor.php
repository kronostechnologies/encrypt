<?php

namespace Kronos\Encrypt\Key\Provider;

interface ProviderAdaptor
{

    /**
     * Return encryption/decryption key
     */
    public function getKey(): string;
}
