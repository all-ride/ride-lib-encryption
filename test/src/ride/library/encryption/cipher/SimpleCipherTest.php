<?php

namespace ride\library\encryption\cipher;

use \PHPUnit_Framework_TestCase;

class SimpleCipherTest extends AbstractCipherTest {

    public function setUp() {
        $this->cipher = new SimpleCipher();
    }

}
