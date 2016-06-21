<?php

namespace ride\library\encryption\cipher;

use ride\library\encryption\exception\EncryptionException;

/**
 * Chain of ciphers to encrypt and decrypt data using an encryption key
 */
class ChainCipher implements Cipher {

    /**
     * Chain of ciphers
     * @var array
     */
    private $chain = array();

    /**
     * Adds a cipher to the chain
     * @param Cipher $cipher Cipher implementation
     * @param integer $iterations Number of iterations over this cipher
     * @return null
     */
    public function addCipher(Cipher $cipher, $iterations = 1) {
        if (!is_integer($iterations) || $iterations < 1) {
            throw new EncryptionException('Could not add cipher: iterations should be a positive integer');
        }

        $this->chain[] = array(
            'cipher' => $cipher,
            'iterations' => $iterations,
        );
    }

    /**
     * Removes a cipher to the chain
     * @param Cipher $cipher Cipher implementation
     * @return null
     */
    public function removeCipher(Cipher $cipher) {
        foreach ($this->chain as $index => $link) {
            if ($link['cipher'] === $cipher) {
                unset($this->chain[$index]);

                return;
            }
        }

        throw new EncryptionException('Could not remove cipher: provided cipher not found in the chain');
    }

    /**
     * Generates a encryption key
     * @return string
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * key could not be generated
     */
    public function generateKey() {
        foreach ($this->chain as $link) {
            return $link['cipher']->generateKey();
        }

        throw new EncryptionException('Could not generate key: no ciphers added to the chain');
    }

    /**
     * Encrypts the plain data with the provided encryption key
     * @param string $data Plain data
     * @param string $key Encryption key
     * @return string Encrypted data
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * data could not be encrypted
     */
    public function encrypt($data, $key) {
        foreach ($this->chain as $link) {
            for ($i = 1; $i <= $link['iterations']; $i++) {
                $data = $link['cipher']->encrypt($data, $key);
            }
        }

        return $data;
    }

    /**
     * Decrypts the encrypted data with the provided encryption key
     * @param string $data Encrypted data
     * @param string $key Encryption key
     * @return string Plain data
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * data could not be decrypted
     */
    public function decrypt($data, $key) {
        $chain = array_reverse($this->chain);

        foreach ($chain as $link) {
            for ($i = 1; $i <= $link['iterations']; $i++) {
                $data = $link['cipher']->decrypt($data, $key);
            }
        }

        return $data;
    }

}
