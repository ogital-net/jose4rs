//! An example showing the use of JSON Web Encryption (JWE) to encrypt and then
//! decrypt some content using a symmetric key and direct encryption.
//!
//! Ported from jose4j's `ExamplesTest.jweRoundTripExample`.

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::JsonWebKey;
use jose4rs::jwx::{HeaderParameter, JsonWebStructure};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The content to be encrypted.
    let message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION!";

    // The shared secret or shared symmetric key represented as an octet
    // sequence JSON Web Key (JWK).
    let jwk_json = r#"{"kty":"oct","k":"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I"}"#;
    let jwk = JsonWebKey::from_json(jwk_json)?;

    // Create a new Json Web Encryption object.
    let mut sender_jwe = JsonWebEncryption::new();

    // The plaintext of the JWE is the message that we want to encrypt.
    sender_jwe.set_payload(message);

    // Set the "alg" header, which indicates the key management mode for this
    // JWE. In this example we are using the direct key management mode, which
    // means the given key will be used directly as the content encryption key.
    sender_jwe.set_algorithm(KeyManagementAlgorithm::Direct);

    // Set the "enc" header, which indicates the content encryption algorithm to
    // be used. This example uses AES_128_CBC_HMAC_SHA_256 which is a
    // composition of AES CBC and HMAC SHA2 that provides authenticated
    // encryption.
    sender_jwe.set_header(
        HeaderParameter::EncryptionMethod,
        ContentEncryptionAlgorithm::Aes128CbcHmacSha256.name(),
    );

    // Set the key on the JWE. In this case, using direct mode, the key will be
    // used directly as the content encryption key. AES_128_CBC_HMAC_SHA_256,
    // which is being used to encrypt the content, requires a 256 bit key.
    sender_jwe.set_key(&jwk);

    // Produce the JWE compact serialization, which is where the actual
    // encryption is done. The JWE compact serialization consists of five
    // base64url encoded parts combined with a dot ('.') character in the
    // general format of
    // <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication tag>
    // Direct encryption doesn't use an encrypted key so that field will be an
    // empty string in this case.
    sender_jwe.encrypt()?;
    let compact_serialization = sender_jwe.compact_serialization()?;

    // Do something with the JWE. Like send it to some other party over the
    // clouds and through the interwebs.
    println!("JWE compact serialization: {compact_serialization}");

    // That other party, the receiver, can then use JsonWebEncryption to
    // decrypt the message.
    let mut receiver_jwe = JsonWebEncryption::new();

    // Set the algorithm constraints based on what is agreed upon or expected
    // from the sender.
    let alg_constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [KeyManagementAlgorithm::Direct]);
    receiver_jwe.set_algorithm_constraints(&alg_constraints);

    // Set the compact serialization on a new Json Web Encryption object.
    receiver_jwe.set_compact_serialization(&compact_serialization)?;

    // Symmetric encryption, like we are doing here, requires that both parties
    // have the same key. The key will have had to have been securely exchanged
    // out-of-band somehow.
    receiver_jwe.set_key(&jwk);

    // Get the message that was encrypted in the JWE. This step performs the
    // actual decryption steps.
    let plaintext = String::from_utf8_lossy(receiver_jwe.payload()?);

    // And do whatever you need to do with the clear text message.
    println!("plaintext: {plaintext}");

    Ok(())
}
