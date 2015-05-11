<?php

namespace ride\library\encryption\cipher;

/**
 * Interface to implement a cipher to encrypt and decrypt data using an encryption key
 */
interface Cipher {

    /**
     * Generates a encryption key
     * @return string
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * key could not be generated
     */
    public function generateKey();

    /**
     * Encrypts the plain data with the provided encryption key
     * @param string $data Plain data
     * @param string $key Encryption key
     * @return string Encrypted data
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * data could not be encrypted
     */
    public function encrypt($data, $key);

    /**
     * Decrypts the encrypted data with the provided encryption key
     * @param string $data Encrypted data
     * @param string $key Encryption key
     * @return string Plain data
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * data could not be decrypted
     */
    public function decrypt($data, $key);

}
