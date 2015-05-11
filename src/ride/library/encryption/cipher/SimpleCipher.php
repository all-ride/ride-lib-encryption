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
    const METHOD = 'blowfish';

    /**
     * Cipher mode
     * @var string
     */
    const MODE = 'cbc';

    /**
     * Size of the checksum hash
     * @var integer
     */
    const CHECKSUM_SIZE = 16;

    /**
     * Constructs a new instance of the cipher
     * @param integer|null $randomSource Source of the initialization vector.
     * The source can be MCRYPT_RAND (system random number generator),
     * MCRYPT_DEV_RANDOM (read data from /dev/random) and MCRYPT_DEV_URANDOM
     * (read data from /dev/urandom). Defaults to MCRYPT_DEV_URANDOM.
     * @return null
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * cipher could not be initialized
     */
    public function __construct($randomSource = null) {
        parent::__construct($randomSource);

        $this->initializationVectorLength = mcrypt_get_iv_size(self::METHOD, self::MODE);
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

        if (!function_exists('mcrypt_list_algorithms')) {
            throw new EncryptionException('Could not create cipher: mcrypt functions are not installed or enabled, check your PHP installation.');
        }

        if (!in_array(self::METHOD, mcrypt_list_algorithms(), true)) {
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

            // add checksum
            $data = $this->addChecksum($data, $key);

            // encrypt the data
            $data = mcrypt_encrypt(self::METHOD, $key, $data, self::MODE, $initializationVector);
            if ($data === false) {
                throw new EncryptionException('Encrypt returned false');
            }

            // add the initialization vector to the encrypted data
            $data = $initializationVector . $data;

            // pack the result
        	$data = $this->pack($data);
        } catch (Exception $exception) {
            throw new EncryptionException('Could not encrypt the provided data', 0, $exception);
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
        try {
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

            // decrypt the data
        	$data = mcrypt_decrypt(self::METHOD, $key, $data, self::MODE, $initializationVector);
            if ($data === false) {
                throw new EncryptionException('Decrypt returned false');
            }
            $data = rtrim($data, "\0");

            // validate checksum
            $data = $this->validateChecksum($data, $key);
        } catch (Exception $exception) {
            throw new EncryptionException('Could not decrypt the provided data', 0, $exception);
        }

        return $data;
    }

    /**
     * Adds a checksum to the provided data
     * @param string $data
     * @return string
     */
    private function addChecksum($data, $key) {
        return $this->getChecksum($data, $key) . '#' . strlen($data) . '#' . $data . '#';
    }

    /**
     * Validates a checksum to the provided data
     * @param string $data Data with checksum
     * @return string Data without the checksum
     * @throws \ride\library\encryption\EncryptionException when the checksum
     * could not be validated
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
     * @return null
     */
    private function getChecksum($data, $key) {
        $checksum = $this->hmac($data, $key, false);
        $checksum = substr($checksum, 0, self::CHECKSUM_SIZE);

        return $checksum;
    }

}
