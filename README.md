# fileshadow
A mathematical algorithm designed to hide files within other files using advanced cryptographic techniques.

### Encryption
Fileshadow is primarily a transformation & obfuscation algorithm rather than a traditional encryption algorithm. While the mutation factor and position of bytes is to cryptographically determined, the data is not encrypted traditionally. For this purpose the use of AES-256-GCM is recommended. This is done by using the ``--gen-aes`` for generating a key (hide only) and ``--with-aes <key>`` flags. You are advised to keep your AES-key and the transformation parameters (.seckey.n) seperated.

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

### Why Mutate at all?
If bytes were not mutated at all one could in theory read them when looking at a byte overview. Despite this being increadibly difficult because the locations of the bytes are completely scrambled, it is not impossible when looking for known sequences in small files. Therefore we mutate, and thus obfuscate, the bytes prior to placing them. By using a value mutation factor we can do this very quickly and by randomizing the parameters of the curve per generation, it becomes significantly harder to recognise the original values & patterns in  the cover data. These parameters form the secret key, and are not so much an encryption key but rather a secret key used for obfuscating/ciphering individual bytes. Thus, increasing segragation of semantic relationships between bytes, and not just in space.

### Note on Cover files
Fileshadow does not do anything to preserve the state of the file you decide to hide data into. This means that it is not recommended to hide in files with critical value, either to you or your system. However, you could very well hide some information in a pdf file or something along those lines. (Or an inactive kernel driver if you feel risky)

