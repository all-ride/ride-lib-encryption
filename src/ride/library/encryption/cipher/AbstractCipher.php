<?php

namespace ride\library\encryption\cipher;

use ride\library\encryption\exception\EncryptionException;

/**
 * Abstract implementation for a cipher
 */
abstract class AbstractCipher implements Cipher {

    /**
     * Hash algorithm for the key derivation (sha256 is recommended)
     * @var string
     */
    const HASH_ALGORITHM = 'sha256';

    /**
     * Required size of the key
     * @var integer
     */
    const KEY_SIZE = 16;

    /**
     * Required length of the initialization vector
     * @var integer
     */
    protected $initializationVectorLength;

    /**
     * Source of the initialization vector.
     * @var integer
     */
    protected $randomSource;

    /**
     * Flag to see if the key should be truncated to required key size
     * @var boolean
     */
    protected $truncateKey = false;

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
        $this->testSystem();

        if ($randomSource === null) {
            $randomSource = MCRYPT_DEV_URANDOM;
        } elseif ($randomSource !== MCRYPT_RAND && $randomSource !== MCRYPT_DEV_RANDOM && $randomSource !== MCRYPT_DEV_URANDOM) {
            throw new EncryptionException('Could not create cipher: invalid random source provided, try MCRYPT_RAND, MCRYPT_DEV_RANDOM or MCRYPT_DEV_URANDOM.');
        }

        $this->randomSource = $randomSource;
    }

    /**
     * Performs tests when unserializing this cipher
     * @return null
     */
    public function __wakeup() {
        $this->testSystem();
    }

    /**
     * Tests the system
     * @return null
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * cipher could not be initialized on this system
     */
    protected function testSystem() {
        if (!function_exists('hash_algos') || !function_exists('hash_hmac')) {
            throw new EncryptionException('Could not create cipher: hash functions are not installed or enabled, check your PHP installation.');
        }
        if (!function_exists('mcrypt_create_iv')) {
            throw new EncryptionException('Could not create cipher: mcrypt functions are not installed or enabled, check your PHP installation.');
        }

        if (ini_get('mbstring.func_overload')) {
            throw new EncryptionException('Could not create cipher: disable mbstring.func_overload in your php.ini.');
        }

        if (!in_array(self::HASH_ALGORITHM, hash_algos(), true)) {
            throw new EncryptionException('Could not create cipher: hash ' . self::HASH_ALGORITHM . ' is not supported.');
        }
    }

    /**
     * Generates a encryption key
     * @return string
     * @throw \ride\library\encryption\exception\EncryptionException when the
     * key could not be generated
     */
    public function generateKey() {
        $key = '';

        $seed = $this->generateRandom(static::KEY_SIZE + 2);
        $seed = bin2hex($seed);

        for ($i = 0; $i < static::KEY_SIZE; $i++) {
            $key .= chr(40 + (hexdec($seed[$i]) + hexdec($seed[$i + 1]) + hexdec($seed[$i + 2])));
        }

        return $key;
    }

    /**
     * Processes the provided encryption key
     * @param string $key Key to validate and process
     * @return string Valid key for a cipher operation
     * @throws \ride\library\encryption\exception\EncryptionException when an
     * invalid key has been provided
     */
    protected function getKey($key) {
        if (!is_string($key)) {
            throw new EncryptionException('Provided key is invalid');
        }

        $keyLength = strlen($key);
        if ($keyLength === 0) {
            throw new EncryptionException('Provided key is empty');
        } elseif ($keyLength < static::KEY_SIZE) {
            throw new EncryptionException('Provided key should be at least ' . static::KEY_SIZE . ' characters long');
        }

        if ($this->truncateKey) {
            $key = substr($key, 0, static::KEY_SIZE);
        }

        return $key;
    }

    /**
     * Generates a keyed hash value using the HMAC method
     * @param string $data
     * @param $key
     * @return string
     * @throws \ride\library\encryption\exception\EncryptionException when the
     * hash could not be generated
     */
    protected function hmac($data, $key, $rawOutput = true) {
        $hmac = hash_hmac(self::HASH_ALGORITHM, $data, $key, $rawOutput);
        if ($hmac === false) {
            throw new EncryptionException('Could not generated a keyed hash');
        }

        return $hmac;
    }

    /**
     * Generates a random string
     * @param integer $length Length for the random string
     * @return string Random string of the provided length
     * @throws \ride\library\encryption\exception\EncryptionException when the
     * random string could not be generated
     */
    protected function generateRandom($length) {
        if (!is_numeric($length) || $length <= 0) {
            throw new EncryptionException('Could not generate random string: invalid length provided');
        }

        $random = mcrypt_create_iv($length, $this->randomSource);
        if ($random === false) {
            throw new EncryptionException('Could not generate random string');
        }

        return $random;
    }

    /**
     * Packs the provided data into a safe string format
     * @param string $data Unpacked data
     * @return string Packed data
     */
    protected function pack($data) {
        $data = base64_encode($data);
        $data = rtrim(strtr($data, '+/', '-_'), '=');

        return $data;
    }

    /**
     * Unpacks the provided data from a safe string format
     * @param string $data Packed data
     * @return string Unpacked data
     */
    protected function unpack($data) {
        $data = str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT);
        $data = base64_decode($data);

        return $data;
    }

    /**
     * Compares two string byte per byte to fight time attacks
     * @param string $string1 First string
     * @param string $string2 Second string
     * @return boolean True when equals, false otherwise
     */
    protected function equals($string1, $string2) {
        $length = strlen($string1);
        if ($length !== strlen($string2)) {
            return false;
        }

        $status = 0;
        for ($i = 0; $i < $length; $i++) {
            $status |= ord($string1[$i]) ^ ord($string2[$i]);
        }

        return $status === 0;
    }

}
