<?php

namespace ride\library\encryption\cipher;

use \PHPUnit_Framework_TestCase;

class GenericCipherTest extends AbstractCipherTest {

    public function setUp() {
        $this->cipher = new GenericCipher();
    }

}
