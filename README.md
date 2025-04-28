# fileshadow
A mathematical algorithm designed to hide files within other files using advanced cryptographic techniques.

### Encryption
Fileshadow is primarily a transformation algorithm rather than a traditional encryption algorithm. While the location of bytes is to cryptographically determined, in order to encrypt the data itself you must make use of AES. This is done by using the ``--gen-aes`` for generating a key (hide only) and ``--with-aes <key>`` flags. You are advised to keep your AES-key and the transformation parameters (.seckey.n) seperated.

### Example Usage
Without AES:
```bash
fileshadow hide example.txt cover.pdf
fileshadow retrieve cover.pdf .seckey.0
```
With AES:
```bash
fileshadow hide example.txt cover.pdf --gen-aes
fileshadow retrieve cover.pdf .seckey.0 --with-aes <prevously_generated_aes_key>
```

### Note on Cover files
Fileshadow does not do anything to preserve the state of the file you decide to hide data into. This means that it is not recommended to hide in files with critical value, either to you or your system. However, you could very well hide some information in a pdf file or something along those lines. (Or an inactive kernel driver if you feel risky)

