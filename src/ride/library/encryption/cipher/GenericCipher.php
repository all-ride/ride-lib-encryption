<?php

namespace ride\library\encryption\cipher;

use ride\library\encryption\exception\EncryptionException;

use \Exception;

/**
 * AES-128 cipher in CBC mode with a SHA-256 HMAC authorization. This cipher
 * should be secure for sensitive data.
 */
final class GenericCipher extends AbstractCipher {

    /**
     * Cipher method and cipher mode
     * @var string
     */
    const METHOD = 'aes-128-cbc';

    /**
     * Size of the authorization part of encrypted data
     * @var integer
     */
    const AUTHORIZATION_SIZE = 32;

    /**
     * Number of iterations for the key derivation (at least 1000 is
     * recommended)
     * @var string
     */
    const HASH_ITERATIONS = 1024;

    /**
     * Raw data constant for backwards compatibility
     * @var integer
     */
    const OPENSSL_RAW_DATA = 1;

    /**
     * Salt for the encryption key derivation
     * @var string
     */
    private $saltEncryption;

    /**
     * Salt for the authorization key derivation
     * @var string
     */
    private $saltAuthorization;

    /**
     * Flag to see if hash_pbkdf2() can used (>= php 5.5.0)
     * @var boolean
     */
    private $isNativePbkdf;

    /**
     * Constructs a new instance of the cipher
     * @param string|null $saltEncryption Salt for the encryption key derivation
     * @param string|null $saltAuthorization Salt for the authorization key
     * derivation
     * @param integer|null $randomSource Source of the initialization vector.
     * The source can be MCRYPT_RAND (system random number generator),
     * MCRYPT_DEV_RANDOM (read data from /dev/random) and MCRYPT_DEV_URANDOM
     * (read data from /dev/urandom). Defaults to MCRYPT_DEV_URANDOM.
     * @return null
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * cipher could not be initialized
     */
    public function __construct($saltEncryption = null, $saltAuthorization = null, $randomSource = null) {
        parent::__construct($randomSource);

        if ($saltEncryption === null) {
            $saltEncryption = '80MEnmD38z5iM5wTO27QRUtziUv3ICRUtziUv3IC';
        } elseif (!is_string($saltEncryption) || strlen($saltEncryption) < self::KEY_SIZE) {
            throw new EncryptionException('Could not create cipher: invalid encryption salt provided, try a string of at least ' . self::KEY_SIZE . ' characters.');
        }

        if ($saltAuthorization === null) {
            $saltAuthorization = 'c2v7xvjowWSTathQwzb4jfqhUXc78dOMusmdQ75i';
        } elseif (!is_string($saltAuthorization) || strlen($saltAuthorization) < self::KEY_SIZE) {
            throw new EncryptionException('Could not create cipher: invalid authorization salt provided, try a string of at least ' . self::KEY_SIZE . ' characters.');
        }

        $this->saltEncryption = $saltEncryption;
        $this->saltAuthorization = $saltAuthorization;

        $this->truncateKey = true;
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
            throw new EncryptionException('Could not create cipher: OpenSSL functions are not installed or enabled, check your PHP installation.');
        }

        if (!in_array(self::METHOD, openssl_get_cipher_methods(), true)) {
            throw new EncryptionException('Could not create cipher: method ' . self::METHOD . ' is not supported.');
        }

        $this->isNativePbkdf = function_exists("hash_pbkdf2");
    }

    /**
     * Encrypts the plain data with the provided encryption key.
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

            // encrypt the data
            $encryptionKey = $this->pbkdf2($key, $this->saltEncryption);
            $data = openssl_encrypt($data, self::METHOD, $encryptionKey, self::OPENSSL_RAW_DATA, $initializationVector);
            if ($data === false) {
                throw new EncryptionException('Encrypt returned false');
            }

            // add the initialization vector to the encrypted data
            $data = $initializationVector . $data;

            // add authorization to the encrypted data
            $authorizationKey = $this->pbkdf2($key, $this->saltAuthorization);
            $authorization = $this->hmac($data, $authorizationKey);
            $data = $authorization . $data;

            // pack the result
            $data = $this->pack($data);
        } catch (Exception $exception) {
            throw new EncryptionException('Could not encrypt the provided data', 0, $exception);
        }

        return $data;
    }

    /**
     * Decrypts the cipher text with the provided encryption key.
     * @param string $data Encrypted data
     * @param string $key Encryption key
     * @return string Plain data
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * data could not be decrypted
     */
    public function decrypt($data, $key) {
        try {
            // make preparations
            $key = $this->getKey($key);
            $data = $this->unpack($data);

            // check for required length
            if (strlen($data) <= (self::AUTHORIZATION_SIZE + $this->initializationVectorLength)) {
                throw new EncryptionException('Encrypted data is invalid');
            }

            // extract authorization from the encrypted data
            $hmac = substr($data, 0, self::AUTHORIZATION_SIZE);
            $data = substr($data, self::AUTHORIZATION_SIZE);
            $authorizationKey = $this->pbkdf2($key, $this->saltAuthorization);
            if ($hmac === false || $data === false) {
                throw new EncryptionException('Authorization could not be extracted');
            }

            // authorize the encrypted data
            $authorizedHmac = $this->hmac($data, $authorizationKey);
            if (!$this->equals($hmac, $authorizedHmac)) {
                throw new EncryptionException('Encrypted data is not authorized');
            }

            // extract the initialization vector from the encrypted data.
            $initializationVector = substr($data, 0, $this->initializationVectorLength);
            $data = substr($data, $this->initializationVectorLength);
            if ($initializationVector === false || $data === false) {
                throw new EncryptionException('Initialization vector could not be extracted');
            }

            // decrypt the data
            $encryptionKey = $this->pbkdf2($key, $this->saltEncryption);
            $data = openssl_decrypt($data, self::METHOD, $encryptionKey, self::OPENSSL_RAW_DATA, $initializationVector);
            if ($data === false) {
                throw new EncryptionException('Decrypt returned false');
            }
        } catch (Exception $exception) {
            throw new EncryptionException('Could not decrypt the provided data', 0, $exception);
        }

        return $data;
    }

    /**
     * Generates a PBKDF2 key derivation of a supplied password
     *
     * PBKDF2 key derivation function as defined by RSA's PKCS #5. Test vectors
     * can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     * @param string $password Password to get the derivation of
     * @param string $salt Salt that is unique to the password
     * @return string Key derived from the password and salt with the requested
     * length
     * @see https://www.ietf.org/rfc/rfc2898.txt
     */
    private function pbkdf2($password, $salt) {
        if ($this->isNativePbkdf) {
            return hash_pbkdf2(self::HASH_ALGORITHM, $password, $salt, self::HASH_ITERATIONS, self::KEY_SIZE, true);
        }

        $hashLength = strlen(hash(self::HASH_ALGORITHM, '', true));
        $blockCount = ceil(self::KEY_SIZE / $hashLength);

        $output = '';
        for ($i = 1; $i <= $blockCount; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack('N', $i);

            // iterations
            $last = $xorsum = $this->hmac($last, $password);
            for ($j = 1; $j < self::HASH_ITERATIONS; $j++) {
                $xorsum ^= ($last = $this->hmac($last, $password));
            }

            $output .= $xorsum;
        }

        return substr($output, 0, self::KEY_SIZE);
    }

}
