<?php

namespace ride\library\encryption\hash;

use ride\library\encryption\exception\EncryptionException;

/**
 * PHP builtin hash implementation
 */
class GenericHash implements Hash {

    /**
     * Name of the algorithm
     * @var string
     */
    protected $algorithm;

    /**
     * Flag to see if raw output should be returned
     * @var boolean
     */
    protected $rawOutput;

    /**
     * Constructs a new hash algorithm
     * @param string $algorithm Name of the algorithm
     * @param boolean $rawOutput Flag to see if raw output should be returned
     * @return null
     * @throws \ride\library\encryption\exception\EncryptionException when the
     * provided algorithm is not available or when hashing is disabled
     */
    public function __construct($algorithm = 'sha256', $rawOutput = false) {
        if (!function_exists('hash_algos')) {
            throw new EncryptionException('Could not create hash algorithm: hashing functions are not enabled, check your PHP installation');
        }

        $availableAlgorithms = hash_algos();
        if (!in_array($algorithm, $availableAlgorithms)) {
            throw new EncryptionException('Could not create hash algorithm: ' . $algorithm . ' is not supported by your PHP installation. Try one of the following: ', implode(', ', $availableAlgorithms));
        }

        $this->algorithm = $algorithm;
        $this->rawOutput = $rawOutput;
    }

    /**
     * Hashes the provided data
     * @param string $data Data to hash
     * @return string Hashed value of the provided string
     */
    public function hash($data) {
        return hash($this->algorithm, $data, $this->rawOutput);
    }

}
