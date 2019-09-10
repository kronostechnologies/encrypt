<?php

namespace Kronos\Encrypt\Key\Provider;

class SimpleKey implements ProviderAdaptor
{

    /**
     * @var string
     */
    private $key;

    /**
     * StringKey constructor.
     * @param string $key Key to hold and give back
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }


    public function getKey(): string
    {
        return $this->key;
    }

}
