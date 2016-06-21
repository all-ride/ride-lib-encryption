<?php

namespace ride\library\encryption\cipher;

use \PHPUnit_Framework_TestCase;

class ChainCipherTest extends AbstractCipherTest {

    public function setUp() {
        $this->cipher = new ChainCipher();
        $this->cipher->addCipher(new GenericCipher(), 5);
        $this->cipher->addCipher(new SimpleCipher(), 5);
        $this->cipher->addCipher(new GenericCipher(), 3);
        $this->cipher->addCipher(new SimpleCipher(), 3);
    }

}
