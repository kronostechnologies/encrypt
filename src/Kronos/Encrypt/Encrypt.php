<?php

namespace Kronos\Encrypt;

class Encrypt
{
    /**
     * @var Cipher\CipherAdaptor
     */
    private $cipher;

    /**
     * @var Key\Provider\ProviderAdaptor
     */
    private $provider;

    /**
     * @param Cipher\CipherAdaptor $cipher
     * @param Key\Provider\ProviderAdaptor $provider
     */
    public function __construct(Cipher\CipherAdaptor $cipher, Key\Provider\ProviderAdaptor $provider)
    {
        $this->cipher = $cipher;
        $this->provider = $provider;
    }

    /**
     * Encrypt plaintext using given cypher and provided key
     *
     * @param string $plaintext
     * @return string
     */
    public function encrypt(string $plaintext): string
    {
        $key = $this->provider->getKey();

        return $this->cipher->encrypt($plaintext, $key);
    }

    /**
     * @param string $cyphertext
     * @return string
     */
    public function decrypt(string $cyphertext): string
    {
        $key = $this->provider->getKey();

        return $this->cipher->decrypt($cyphertext, $key);
    }
}
