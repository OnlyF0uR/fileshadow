# fileshadow
A mathematical algorithm designed to hide files within other files using advanced cryptographic techniques.

### Note of Caution
Fileshadow is primarily a transformation algorithm rather than a traditional encryption algorithm. While the location of bytes is to cryptographically determined, in order to encrypt the data itself you must make use of AES. This can be done by using the ``--gen-aes`` for generating a key (hide only) or ``--with-aes <key>`` flags.

