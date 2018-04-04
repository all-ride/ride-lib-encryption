<?php

namespace ride\library\encryption\cipher;

use ride\library\encryption\exception\EncryptionException;

use \Exception;

/**
 * Blowfish cipher in CBC mode with a SHA-256 HMAC checksum. This cipher is
 * NOT SECURE for sensitive data. However, it's URL safe and may be useful for
 * it's relative short length of encrypted data.
 */
final class SimpleCipher extends AbstractCipher {

    /**
     * Cipher algorithm
     * @var string
     */
    const METHOD = 'bf-cbc';

    /**
     * Size of the checksum hash
     * @var integer
     */
    const CHECKSUM_SIZE = 16;

    /**
     * Constructs a new instance of the cipher
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * cipher could not be initialized on this system
     */
    public function __construct() {
        parent::__construct();

        $this->initializationVectorLength = openssl_cipher_iv_length(self::METHOD);
        if ($this->initializationVectorLength === false || $this->initializationVectorLength <= 0) {
            throw new EncryptionException('Could not create cipher: invalid initialization vector length received.');
        }
    }

    /**
     * Tests the system
     * @return null
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * cipher could not be initialized on this system
     */
    protected function testSystem() {
        parent::testSystem();

        if (!function_exists('openssl_get_cipher_methods')) {
            throw new EncryptionException('Could not create cipher: SSL functions are not installed or enabled, check your PHP installation.');
        }

        if (!in_array(self::METHOD, openssl_get_cipher_methods(), true)) {
            throw new EncryptionException('Could not create cipher: method ' . self::METHOD . ' is not supported.');
        }
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
        try {
            // make preparations
            $key = $this->getKey($key);
            $initializationVector = $this->generateRandom($this->initializationVectorLength);

            $data = $this->performEncrypt($data, $key, $initializationVector);
        } catch (Exception $exception) {
            throw new EncryptionException('Could not encrypt the provided data', 0, $exception);
        }

        return $data;
    }

    /**
     * Perform the actual encryption
     * @param string $data Plain data
     * @param string $key Validated key
     * @param string $initializationVector Random string for the encryption
     * @return string Decrypted data
     */
    private function performEncrypt($data, $key, $initializationVector) {
        // add checksum
        $data = $this->addChecksum($data, $key);

        // encrypt the data
        $data = openssl_encrypt($data, self::METHOD, $key, 0, $initializationVector);
        if ($data === false) {
            throw new EncryptionException('Encrypt returned false');
        }

        // add the initialization vector to the encrypted data
        $data = $initializationVector . $data;

        // pack the result
    	return $this->pack($data);
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
        try {
            // keep incoming data for validation at the end
            $inData = $data;

            // make preparations
            $data = $this->unpack($data);
            $key = $this->getKey($key);

            // check length
            if (strlen($data) <= $this->initializationVectorLength) {
                throw new EncryptionException('Encrypted data is invalid');
            }

            // extract the initialization vector from the encrypted data.
            $initializationVector = substr($data, 0, $this->initializationVectorLength);
            $data = substr($data, $this->initializationVectorLength);
            if ($initializationVector === false || $data === false) {
                throw new EncryptionException('Initialization vector could not be extracted');
            }

            $data = $this->performDecrypt($data, $key, $initializationVector);

            // validate encrypted data
            if ($inData !== $this->performEncrypt($data, $key, $initializationVector)) {
                throw new EncryptionException('Encrypted data is tampered with: "' . $data . '"');
            }
        } catch (Exception $exception) {
            throw new EncryptionException('Could not decrypt the provided data', 0, $exception);
        }

        return $data;
    }

    /**
     * Perform the actual decryption
     * @param string $data Encrypted data withouth the initialization vector
     * @param string $key Validated key
     * @param string $initializationVector Random string for the encryption
     * @return string Decrypted data
     */
    private function performDecrypt($data, $key, $initializationVector) {
        // decrypt the data
    	$data = openssl_decrypt($data, self::METHOD, $key, 0, $initializationVector);
        if ($data === false) {
            throw new EncryptionException('Decrypt returned false');
        }

        $data = rtrim($data, "\0");

        // validate checksum
        return $this->validateChecksum($data, $key);
    }

    /**
     * Adds a checksum to the provided data
     * @param string $data
     * @param string $key
     * @return string
     */
    private function addChecksum($data, $key) {
        return $this->getChecksum($data, $key) . '#' . strlen($data) . '#' . $data . '#';
    }

    /**
     * Validates a checksum to the provided data
     * @param string $data Data with checksum
     * @param string $key
     * @return string Data without the checksum
     * @throws \ride\library\encryption\exception\EncryptionException when the
     * checksum could not be validated
     */
    private function validateChecksum($data, $key) {
        // check trailing #
        $lastChar = substr($data, -1);
        if ($lastChar !== '#') {
            throw new EncryptionException('Encrypted data is invalid');
        }
        $data = substr($data, 0, -1);

        // get checksum and length
        if (strpos($data, '#') !== self::CHECKSUM_SIZE) {
            throw new EncryptionException('Checksum not found');
        }

        $checksum = explode('#', $data);
        if (count($checksum) < 3) {
            throw new EncryptionException('Checksum is invalid');
        }

        $length = $checksum[1];
        $checksum = $checksum[0];
        $data = substr($data, self::CHECKSUM_SIZE + strlen('#' . $length . '#'));

        // validate checksum and length
        if ($length != strlen($data) || !$this->equals($checksum, $this->getChecksum($data, $key))) {
            throw new EncryptionException('Checksum does not match');
        }

        return $data;
    }

    /**
     * Creates a checksum for the provided data
     * @param string $data
     * @param string $key
     * @return string
     */
    private function getChecksum($data, $key) {
        $checksum = $this->hmac($data, $key, false);
        $checksum = substr($checksum, 0, self::CHECKSUM_SIZE);

        return $checksum;
    }

}
