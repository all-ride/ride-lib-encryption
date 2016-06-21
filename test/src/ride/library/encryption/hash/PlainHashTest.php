<?php

namespace ride\library\encryption\hash;

use \PHPUnit_Framework_TestCase;

class PlainHashTest extends PHPUnit_Framework_TestCase {

    /**
     * @dataProvider providerHash
     */
    public function testHash($value) {
        $hash = new PlainHash();

        $this->assertEquals($value, $hash->hash($value));
    }

    public function providerHash() {
        return array(
            array('value'),
            array(null),
        );
    }

}
