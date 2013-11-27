<?php

namespace pallo\library\encryption\hash;

/**
 * Plain text hash implementation
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