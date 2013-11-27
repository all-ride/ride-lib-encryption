<?php

namespace pallo\library\encryption\hash;

/**
 * Interface for cryptographic hash algorithms. These are methods which take an
 * arbitrary block of data and return a fixed-size bit string
 */
interface Hash {

    /**
     * Hashes the provided data
     * @param string $data Data to hash
     * @return string Hashed value
     */
    public function hash($string);

}