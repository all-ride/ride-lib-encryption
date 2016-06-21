<?php

namespace ride\library\encryption\hash;

use \PHPUnit_Framework_TestCase;

class GenericHashTest extends PHPUnit_Framework_TestCase {

    /**
     * @dataProvider providerConstructThrowsExceptionWhenInvalidAlgorithmProvided
     * @expectedException ride\library\encryption\exception\EncryptionException
     */
    public function testConstructThrowsExceptionWhenInvalidAlgorithmProvided($algorithm) {
        new GenericHash($algorithm);
    }

    public function providerConstructThrowsExceptionWhenInvalidAlgorithmProvided() {
        return array(
            array('unexistant'),
            array(null),
            array(array('test')),
            array($this),
        );
    }

    /**
     * @dataProvider providerHash
     */
    public function testHash($expected, $value, $algorithm) {
        $hash = new GenericHash($algorithm);

        $this->assertEquals($expected, $hash->hash($value));
    }

    public function providerHash() {
        return array(
            array(md5('value'), 'value', 'md5'),
            array(sha1('value'), 'value', 'sha1'),
            array(hash('sha256', 'value'), 'value', 'sha256'),
            array(hash('sha512', 'value'), 'value', 'sha512'),
        );
    }

}
