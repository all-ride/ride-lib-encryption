<?php

namespace ride\library\encryption\cipher;

use \PHPUnit_Framework_TestCase;

abstract class AbstractCipherTest extends PHPUnit_Framework_TestCase {

    public function providerData() {
        return array(
            array(15),
            array("EnCrYpT EvErYThInG\x00\x00"),
            array('A super secret message'),
            array('My super duper secret message'),
            array('A super secret message which is a bit more expaned and long and long and long and long and zzz ...  zzz    ...   z z z z ...'),
        );
    }

    /**
     * @dataProvider providerData
     */
    public function testEncryptDecrypt($data, $key = null) {
        if ($key === null) {
            $key = $this->cipher->generateKey();
        }

        $encrypted = $this->cipher->encrypt($data, $key);
        $decrypted = $this->cipher->decrypt($encrypted, $key);

        $this->assertEquals($decrypted, $data);

        // echo "\n" . $encrypted . "\n";
    }

    /**
     * @dataProvider providerData
     * @expectedException ride\library\encryption\exception\EncryptionException
     */
    public function testDecryptFailsOnAppendedData($data, $key = null) {
        if ($key === null) {
            $key = $this->cipher->generateKey();
        }

        $data = $encrypted = $this->cipher->encrypt($data, $key);
        $encrypted .= 'a';

        $this->cipher->decrypt($encrypted, $key);
    }

    /**
     * @dataProvider providerData
     * @expectedException ride\library\encryption\exception\EncryptionException
     */
    public function testDecryptFailsOnChangedData($data, $key = null) {
        if ($key === null) {
            $key = $this->cipher->generateKey();
        }

        $encrypted = $this->cipher->encrypt($data, $key);
        $encrypted[0] = chr((ord($encrypted[0]) + 1) % 256);

        $this->cipher->decrypt($encrypted, $key);
    }

    /**
     * @dataProvider providerData
     * @expectedException ride\library\encryption\exception\EncryptionException
     */
    public function testDecryptFailsOnInvalidKey($data, $key = null) {
        if ($key === null) {
            $key = $this->cipher->generateKey();
        }

        $encrypted = $this->cipher->encrypt($data, $key);
        $key = 'ultrasuperrevealedkey';

        $this->cipher->decrypt($encrypted, $key);
    }

}
