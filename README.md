
# SecureTCP

Base TCP server framework for Windows that incorperates authenticated encryption.


## Network Analysis

SecureTCP uses Authenticated Encryption with Additional Data (AEAD) scheme, specifically Poly1305 and XSalsa20 algorithms, for encryption.
 
AEAD ensures confidentiality, integrity, and authenticity of the encrypted data, and the Poly1305 and XSalsa20 algorithms provide strong and efficient cryptographic security.

![App Screenshot](https://i.ibb.co/KDKPvt8/Secure-TCP-Media.png)


## License

[GNU General Public License v3.0](https://github.com/soundthesamefr/SecureTCP/blob/master/license/)

## Caution
It's not recommended to use this as it is in production, this is purely a proof-of-concept and has many components missing.
