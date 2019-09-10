<?php

namespace Kronos\Tests\Encrypt\Key\Provider;

use Kronos\Encrypt\Key\Provider\SimpleKey;
use PHPUnit\Framework\TestCase;

class SimpleKeyTest extends TestCase {
	const KEY = 'key';

	public function test_getKey_ShouldReturnGivenKey() {
		$simple_key = new SimpleKey(self::KEY);

		$actual_key = $simple_key->getKey();

		$this->assertEquals(self::KEY, $actual_key);
	}
}
