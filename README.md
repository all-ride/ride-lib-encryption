# Ride: Encryption Library

Encryption library of the PHP Ride framework.

## What's In This Library

### Cipher

The _Cipher_ interface is used to implement a cipher to encrypt and decrypt data using an encryption key.

Available implementations:

* ride\library\encryption\cipher\ChainCipher: Chain of ciphers with an certain amount of iterations
* ride\library\encryption\cipher\GenericCipher: Generic implementation
* ride\library\encryption\cipher\SimpleCipher: Simple implementation with relative short length of encrypted data, not secure for sensitive data

### Hash

The _Hash_ interface is used to implement cryptographic hash algorithms. 
These are methods which take an arbitrary block of data and return a fixed-size bit string

Available implementations:

* ride\library\encryption\hash\GenericHash: Use installed hash functions, defaults to SHA256
* ride\library\encryption\hash\PlainHash: For testing purposes

## Code Sample

Check this code sample to see the possibilities of this library:

```php
<?php

use ride\library\encryption\cipher\GenericCipher;
use ride\library\encryption\exception\EncryptionException;
use ride\library\encryption\hash\GenericHash;

// cipher to encrypt and decrypt data
try {
    $cipher = new GenericCiper();
    $data = "Top secret mission";
    
    // if you don't have a secret key, you can generate one
    $key = $cipher->generateKey();
    
    $encrypted = $cipher->encrypt($data, $key);
    $decrypted = $cipher->decrypt($encrypted, $key); 
} catch (EncryptionException $exception) {
    // something's up!
}

// hash to generate a code of fixed size, good for passwords
$hash = new GenericHash();
$data = $hash->hash($data); 
```

## Installation

You can use [Composer](http://getcomposer.org) to install this library.

```
composer require ride/lib-encryption
```
