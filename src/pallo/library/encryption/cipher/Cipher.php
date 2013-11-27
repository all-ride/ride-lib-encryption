<?php

namespace pallo\library\encryption\cipher;

/**
 * Interface to implement a cipher to encrypt and decrypt data using an encryption key
 */
interface Cipher {

    /**
     * Encrypts the plain data with the provided encryption key
     * @param string $data Plain data
     * @param string $key Encryption key
     * @return string Encrypted data
     */
    public function encrypt($data, $key);

    /**
     * Decrypts the encrypted data with the provided encryption key
     * @param string $data Encrypted data
     * @param string $key Encryption key
     * @return string Plain data
     */
    public function decrypt($data, $key);

}