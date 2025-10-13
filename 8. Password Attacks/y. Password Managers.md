## How does a password manager work?

The implementation of password managers varies by provider, but most operate using a master password to encrypt the password database.

The Encryption and authentication rely on us [cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) and [key derivation functions](https://en.wikipedia.org/wiki/Key_derivation_function) to prevent unauthorized access to the encrypted database and its content. The specific mechanisms used depend on the provider and whether the password manager is cloud-based or locally stored.

Let's break down some common password managers and how they work.

## Cloud password managers
One of the key considerations when choosing a password manager is convenience. The average person owns three or four devices and uses them to log into different websites and applications. A cloud-based password manager allows users to synchronize their encrypted password database across multiple devices. Most of them provide:
- A mobile application.
- A browser add-on.
- Some other features that we'll discuss later in this section.

A common implementation for cloud password managers involves deriving encryption keys from the master password. This approach supports [Zero-Knowledge Encryption](https://blog.cubbit.io/blog-posts/what-is-zero-knowledge-encryption), which ensures that no one, not even the service provider, can access your secured data.

## Local password managers
Local password managers provide this option by storing the password database locally and placing the responsibility on the user to protect its content and storage location.
Local password managers use encryption methods similar to those of cloud-based implementations. The most notable difference lies in data transmission and authentication. To encrypt the database, local password managers focus on securing the database stored on the local system, using various cryptographic hash functions (depending on the manufacturer).

