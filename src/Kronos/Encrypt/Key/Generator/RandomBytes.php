<?php

namespace Kronos\Encrypt\Key\Generator;


use Kronos\Encrypt\Key\Exception\GenerateException;

class RandomBytes {
	public function generateKey() {
		if(function_exists('random_bytes')) {
			return random_bytes(256);
		}
		else if(function_exists('openssl_random_pseudo_bytes')) {
			return openssl_random_pseudo_bytes(256);
		}
		else {
			throw new GenerateException('No cryptographically strong algorithm available.');
		}
	}
}