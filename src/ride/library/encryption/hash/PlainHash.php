<?php

namespace ride\library\encryption\hash;

/**
 * Plain text hash implementation for testing purposes
 */
class PlainHash implements Hash {

    /**
     * Hashes the provided data
     * @param string $data Data to hash
     * @return string Provided string untouched
     */
    public function hash($data) {
        return $data;
    }

}
