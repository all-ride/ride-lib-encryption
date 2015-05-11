# Ride: Encryption Library

This library provides interfaces for cipher and hash implementations. 
Some implementations are provided to make it useful out of the box. 

## Code Sample

Check this code sample to see the possibilities of this library:

    <?php
    
    use ride\library\encryption\cipher\GenericCipher;
    use ride\library\encryption\exception\EncryptionException;
    use ride\library\encryption\hash\GenericHash;

    // cipher to encrypt and decrypt data
    $cipher = new GenericCiper();
    $data = "Top secret mission";
    
    // if you don't have a secret key, you can generate one
    $key = $cipher->generateKey();
    
    try {
        $encrypted = $cipher->encrypt($data, $key);
        $decrypted = $cipher->decrypt($encrypted, $key); 
    } catch (EncryptionException $exception) {
        // something's up!
    }

    // hash to generate a code of fixed size, good for passwords
    $hash = new GenericHash();
    $data = $hash->hash($data); 
    
    
    