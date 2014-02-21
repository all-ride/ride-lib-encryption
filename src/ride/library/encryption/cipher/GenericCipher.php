<?php

namespace ride\library\encryption\cipher;

/**
 * Generic URL-safe cipher
 */
class GenericCipher implements Cipher {

    /**
     * Encrypts the plain data with the provided encryption key.
     * @param string $data Plain data
     * @param string $key Encryption key
     * @return string Encrypted data
     */
    public function encrypt($data, $key) {
        $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND));

        return rtrim(strtr(base64_encode($encrypted), '+/', '-_'), '=');
    }

    /**
     * Decrypts the cipher text with the provided encryption key.
     * @param string $data Encrypted data
     * @param string $key Encryption key
     * @return string Plain data
     */
    public function decrypt($data, $key) {
    	$encrypted = base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));

    	return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $encrypted, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
    }

}