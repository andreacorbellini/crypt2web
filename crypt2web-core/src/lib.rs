// Copyright 2020 Andrea Corbellini
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![doc(test(attr(deny(warnings))))]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(unused_qualifications)]

//! Crypt2web: tool for encrypting content that can be decrypted in a web browser (core library).
//!
//! Crypt2web encrypts your files using a password and produces web pages that can be viewed and decrypted using any
//! modern web browser. These web pages are self-contained (no external scripts or dependencies) and make use of
//! WebAssembly for fast decryption operations.
//!
//! Crypt2web uses [ChaCha20] and [Poly1305] for encryption, and [Argon2] for key derivation.
//!
//! This package contains the core functionality used by both the command line client and the WebAssembly client.
//!
//! [WebAssembly]: https://webassembly.org/
//! [ChaCha20]: https://en.wikipedia.org/wiki/ChaCha20
//! [Poly1305]: https://en.wikipedia.org/wiki/Poly1305
//! [Argon2]: https://en.wikipedia.org/wiki/Argon2
//!
//! # Example
//!
//! ```
//! use crypt2web_core::{encrypt, decrypt};
//!
//! let content = b"This is some content to be encrypted. \
//!                 It can be arbitrary long, and contain any sequence of bytes.";
//! let mime_type = "text/plain";
//!
//! let encrypted = encrypt("password", content, mime_type);
//!
//! let (decrypted_content, decrypted_mime_type) = decrypt("password", &encrypted)
//!     .expect("decryption failed");
//! assert_eq!(&decrypted_content[..], &content[..]);
//! assert_eq!(decrypted_mime_type, mime_type);
//! ```

use argon2::Argon2;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use chacha20poly1305::Tag;
use chacha20poly1305::aead::AeadInPlace;
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::io::Read;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const CONTENT_LEN_SIZE: usize = 8;

const HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE + CONTENT_LEN_SIZE;

const ARGON2_M_COST: u32 = 19_456u32;
const ARGON2_P_COST: u32 = 1u32;
const ARGON2_T_COST: u32 = 2u32;

/// Error returned by [`decrypt`].
///
/// [`decrypt`]: fn.decrypt.html
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The ciphertext is corrupted or invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use crypt2web_core::{DecryptError, decrypt};
    ///
    /// assert_eq!(decrypt("password", b"invalid ciphertext"),
    ///            Err(DecryptError::InvalidCiphertext));
    /// ```
    InvalidCiphertext,
    /// The password provided to [`decrypt`] is not the same password used to encrypt the content.
    ///
    /// [`decrypt`]: fn.decrypt.html
    ///
    /// # Example
    ///
    /// ```
    /// use crypt2web_core::{DecryptError, decrypt, encrypt};
    ///
    /// let encrypted = encrypt("password", b"secret", "text/plain");
    /// assert_eq!(decrypt("wrong password", &encrypted),
    ///            Err(DecryptError::InvalidPassword));
    /// ```
    InvalidPassword,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCiphertext => f.write_str("Invalid ciphertext format"),
            Self::InvalidPassword   => f.write_str("Invalid password"),
        }
    }
}

impl Error for DecryptError {
}

fn derive_key(salt: &[u8], password: &str) -> Key {
    let mut key = [0u8; 32];
    let password = password.as_bytes();
    let params = argon2::Params::new(ARGON2_M_COST,
                                     ARGON2_T_COST,
                                     ARGON2_P_COST,
                                     Some(key.len()))
                                .expect("failed to instantiate argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
           .hash_password_into(password, salt, &mut key)
           .expect("failed to derive encryption key using argon2");
    *Key::from_slice(&key)
}

/// Encrypt some content with a password.
///
/// The content can be accompanied by its MIME type (such has `text/plain`). Both the content and the MIME type are
/// encrypted and can be only retrieved by calling [`decrypt`] with the correct password.
///
/// See the [crate documentation] for a full example on how to encrypt and decrypt content.
///
/// [`decrypt`]: fn.decrypt.html
/// [crate documentation]: index.html
///
/// # Examples
///
/// Encrypting some text:
/// ```
/// use crypt2web_core::encrypt;
/// encrypt("password", b"Hello!", "text/plain");
/// ```
///
/// Any parameter is optional and can be blank (including the password field). Also, the MIME type is not validated and
/// can be an arbitrary string:
/// ```
/// # use crypt2web_core::encrypt;
/// encrypt("password", b"This content has no MIME type", "");
/// encrypt("", b"Encrypted with an empty password", "text/plain");
/// encrypt("password", b"", "This is an arbitrary string");
/// ```
///
/// Passwords can be arbitrary Unicode strings:
/// ```
/// # use crypt2web_core::encrypt;
/// encrypt("🍉", b"Hello!", "text/plain");
pub fn encrypt(password: &str, content: &[u8], mime_type: &str) -> Vec<u8> {
    let salt: [u8; SALT_SIZE] = rand::thread_rng().gen();
    let nonce: [u8; NONCE_SIZE] = rand::thread_rng().gen();

    let key = derive_key(&salt, password);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut ciphertext = Vec::with_capacity(
        HEADER_SIZE + content.len() + mime_type.len());
    ciphertext.extend_from_slice(&salt);
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&[0u8; TAG_SIZE]);
    ciphertext.extend_from_slice(&(content.len() as u64).to_le_bytes());
    ciphertext.extend_from_slice(content);
    ciphertext.extend_from_slice(mime_type.as_bytes());

    let nonce = Nonce::from_slice(&nonce);
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext[HEADER_SIZE..])
                    .expect("encryption failed");
    ciphertext[SALT_SIZE + NONCE_SIZE..SALT_SIZE + NONCE_SIZE + TAG_SIZE].copy_from_slice(&tag);

    ciphertext
}

/// Decrypt some content previously encrypted with a password.
///
/// This method lets you retrieve the original content and MIME type that was encrypted using [`encrypt`].
///
/// See the [crate documentation] for a full example on how to encrypt and decrypt content.
///
/// [`encrypt`]: fn.encrypt.html
/// [crate documentation]: index.html
///
/// # Examples
///
/// Decrypting:
/// ```
/// use crypt2web_core::decrypt;
///
/// let encrypted = base64::decode("6JM4NfOYE7TwGJOhAHsNeEU7dSMr7mi\
///                                 8qg9HBDMo6TYLeWB0fcwcq2OQjxcGAA\
///                                 AAAAAAAJUgqaie4u0lSDeXVXhzRFk=")
///                        .unwrap();
///
/// let (content, mime_type) = decrypt("password", &encrypted).expect("decryption failed");
/// assert_eq!(content, b"Hello!");
/// assert_eq!(mime_type, "text/plain");
/// ```
///
/// Attempting to decrypt with the wrong password results in a [`InvalidPassword`] error:
/// ```
/// # use crypt2web_core::decrypt;
/// #
/// # let encrypted = base64::decode("qdmFh7n3FU9MWtHjNi2m7HCg4ETTULm\
/// #                                 Z1hyRHAjINt7M0L7z+6Z8RuhjQoMGAA\
/// #                                 AAAAAAAGDCrclKMbJG2bXf3fLng/Q=")
/// #                        .unwrap();
/// #
/// use crypt2web_core::DecryptError;
/// let result = decrypt("wrong password", &encrypted);
/// assert_eq!(result, Err(DecryptError::InvalidPassword));
/// ```
///
/// Attempting to decrypt something that is not a blob returned by [`encrypt`] results in a [`InvalidCiphertext`]
/// error:
/// ```
/// # use crypt2web_core::{DecryptError, decrypt};
/// let result = decrypt("password", b"wrong ciphertext");
/// assert_eq!(result, Err(DecryptError::InvalidCiphertext));
/// ```
///
/// [`InvalidCiphertext`]: enum.DecryptError.html#variant.InvalidCiphertext
/// [`InvalidPassword`]: enum.DecryptError.html#variant.InvalidPassword
pub fn decrypt(password: &str, mut ciphertext: &[u8]) -> Result<(Vec<u8>, String), DecryptError> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    let mut tag = [0u8; TAG_SIZE];
    let mut content_len = [0u8; CONTENT_LEN_SIZE];

    ciphertext.read_exact(&mut salt)
              .map_err(|_| DecryptError::InvalidCiphertext)?;
    ciphertext.read_exact(&mut nonce)
              .map_err(|_| DecryptError::InvalidCiphertext)?;
    ciphertext.read_exact(&mut tag)
              .map_err(|_| DecryptError::InvalidCiphertext)?;
    ciphertext.read_exact(&mut content_len)
              .map_err(|_| DecryptError::InvalidCiphertext)?;

    let key = derive_key(&salt, password);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut plaintext = ciphertext.to_vec();

    let nonce = Nonce::from_slice(&nonce);
    let tag = Tag::from_slice(&tag);
    cipher.decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
          .map_err(|_| DecryptError::InvalidPassword)?;

    let content_len = u64::from_le_bytes(content_len) as usize;
    let mime_type = String::from_utf8(plaintext[content_len..].to_vec())
                           .map_err(|_| DecryptError::InvalidCiphertext)?;
    plaintext.truncate(content_len);

    Ok((plaintext, mime_type))
}

#[cfg(test)]
mod tests {
    mod simple {
        use crate::DecryptError;
        use crate::decrypt;
        use crate::encrypt;

        #[test]
        fn encrypt_decrypt() {
            let blob = encrypt("s3cret", b"hello", "text/plain");
            let (plain, mime) = decrypt("s3cret", &blob).expect("decrypt failed");
            assert_eq!(plain, b"hello");
            assert_eq!(mime, "text/plain");
        }

        #[test]
        fn invalid_password() {
            let blob = encrypt("s3cret", b"hello", "text/plain");
            let err = decrypt("wrong", &blob).expect_err("decrypt should have failed");
            assert_eq!(err, DecryptError::InvalidPassword);
        }

        #[test]
        fn invalid_mime() {
            let invalid = [0xff, 0xfe, 0xfd];
            String::from_utf8(invalid.to_vec()).expect_err("should be an invalid utf-8 sequence");
            let mime = unsafe { String::from_utf8_unchecked(invalid.to_vec()) };

            let blob = encrypt("s3cret", b"hello", &mime);
            let err = decrypt("s3cret", &blob).expect_err("decrypt should have failed");
            assert_eq!(err, DecryptError::InvalidCiphertext);
        }

        #[test]
        fn invalid_blob() {
            let blob = b"abc";
            let err = decrypt("wrong", blob).expect_err("decrypt should have failed");
            assert_eq!(err, DecryptError::InvalidCiphertext);
        }

        #[test]
        fn indistinguishability() {
            let cipher1 = encrypt("password", b"message", "some/type");
            let cipher2 = encrypt("password", b"message", "some/type");
            assert_ne!(cipher1, cipher2);

            let plain1 = decrypt("password", &cipher1);
            let plain2 = decrypt("password", &cipher2);
            assert_eq!(plain1, plain2);
        }
    }

    mod random {
        use crate::DecryptError;
        use crate::decrypt;
        use crate::encrypt;
        use itertools::Itertools;
        use rand::prelude::*;
        use std::ops::Range;

        fn random_bytes(min_size: usize, max_size: usize) -> Vec<u8> {
            let mut rng = thread_rng();
            let size = rng.gen_range(min_size..max_size);
            (0..size).map(|_| rng.gen::<u8>()).collect()
        }

        fn random_string(min_size: usize, max_size: usize) -> String {
            let mut rng = thread_rng();
            let size = rng.gen_range(min_size..max_size);
            (0..size).map(|_| rng.gen::<char>()).collect()
        }

        fn fuzz(bytes: &mut [u8]) {
            if bytes.is_empty() {
                return;
            }

            let mut rng = thread_rng();
            let rounds = rng.gen_range(1..1024);

            for _ in 0..rounds {
                let index = rng.gen_range(0..bytes.len());
                let bit = rng.gen_range(0..8);
                bytes[index] ^= 1 << bit;
            }
        }

        fn random_test(password_size: Range<usize>, mime_size: Range<usize>, plaintext_size: Range<usize>) {
            let password = random_string(password_size.start, password_size.end);
            let mime = random_string(mime_size.start, mime_size.end);
            let content = random_bytes(plaintext_size.start, plaintext_size.end);

            let encrypted = encrypt(&password, &content, &mime);
            let decrypted = decrypt(&password, &encrypted).expect("decrypt failed");
            assert_eq!(decrypted, (content, mime));

            let mut encrypted = encrypted;
            fuzz(&mut encrypted);
            let err = decrypt(&password, &encrypted).expect_err("decrypt should have failed");
            assert_eq!(err, DecryptError::InvalidPassword);
        }

        #[test]
        fn small() {
            for _ in 0..10 {
                random_test(0..10, 0..10, 0..10);
            }
        }

        #[test]
        fn medium() {
            for _ in 0..10 {
                random_test(0..1024, 0..1024, 16..4096);
            }
        }

        #[test]
        fn large() {
            for _ in 0..10 {
                random_test(0..4096, 0..4096, (16 * 1024)..(512 * 1024));
            }
        }

        #[test]
        fn mix() {
            let ranges = [
                0..16,
                16..4096,
                (16 * 1024)..(512 * 1024),
            ];
            for _ in 0..3 {
                for v in ranges.iter().combinations_with_replacement(3) {
                    random_test(v[0].clone(), v[1].clone(), v[2].clone());
                }
            }
        }
    }

    mod compatibility {
        use crate::decrypt;

        #[test]
        fn blob_0() {
            let blob = base64::decode("JI3jRjOYcBMbf9cpMr8Vfkv+bdtiQ4+NIUmcdjVaxOm1WwNauSK6zX01PVkAAAAAAAAAAA==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_1() {
            let blob = base64::decode("dUZ6of7ZHvquWWYZ/jTXb+vQvvOQlgR5/m2mvjbt5f4fSfnEfiJqhoMoPcAAAAAAAAAAAA==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("s3cret", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_2() {
            let blob = base64::decode("zDGY0IDlAfBiNtrwvvh4mi/NJ6ENkdHSiIoXHr5d9Ng7BIECWRVPgyyvQH8FAAAAAAAAAF\
                                       1k9N5N")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("pass", &blob).expect("decrypt failed");
            assert_eq!(plain, b"hello");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_3() {
            let blob = base64::decode("9S2PnnjRXSPDgr/zuaXv7I0XlhQ2FTkjKIS2TVRsi7hVdLKY57E8Xjh4itQAAAAAAAAAAL\
                                       y8fW5pnW1ImA==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("word", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "mime/type");
        }

        #[test]
        fn blob_4() {
            let blob = base64::decode("zez5of38mMxk1ytjnPZ0ntbUt2Hu+LbLgPhAmK6HvC31u4FbbzV2heRFDaAnAAAAAAAAAB\
                                       ih+ldODbhNKgEBWUhOAlfLjtZcSR9t2A1Zm4OCVa8OgwLALea8jXuHGcZ7wpPlWjU=")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("🍕🍨🍉", &blob).expect("decrypt failed");
            assert_eq!(plain[..], b"This is protected by a Unicode password"[..]);
            assert_eq!(mime, "text/plain");
        }

        #[test]
        fn blob_5() {
            let blob = base64::decode("PLmr18U0at4IW7YJRW2aS+pX26XCLBlaP2ZGyVtgAZTDqb56jjwdC+vm2DEAAQAAAAAAAE\
                                       9KW9RNnWGvoNXd4w1vtgNmES1mj4RaGMdhEbloPfoae2cr5doU1PtLIYdGaqBQdjGa9IE9\
                                       yqiWVP49644fQcso+X47qLp9j7N7YWSRuuxzMB/l0oA66yJlo2kCu48W+dqlauh0hp1aK4\
                                       JPjxhdavUwYaXg53hcts4yZl1oSATgE9+8SVTCzmtBWJ3em5e3ZScCXW8jDD9Yw/QjBS+m\
                                       ymLgTs9KWAuI1saj/6LV1FX54MEHwNAl0SMHc58hEP1O9yh4Aib7noIWVXgPltNvBLB69s\
                                       Zx7oKDAOYXshnX+ANHh51uT3WuF3LyPj1/IPfbYs76w8SdRmoEG6/lxjqn8X0lqL0i2Jxg\
                                       pIw=")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("Some Password", &blob).expect("decrypt failed");
            assert_eq!(plain, (0..=std::u8::MAX).collect::<Vec<u8>>());
            assert_eq!(mime, "Some Mime");
        }

        #[test]
        fn blob_6() {
            let blob = base64::decode("ShpvQccyaIlukpjGkDq0LW3XdDqve0c1LVFwUFYKn0zILtcAZ5k3ilzYeyYABAAAAAAAAI\
                                       dc4zaMd5w+PPweaeLB/k1NqDx1od+SiWL4VGxpaM2gO7Y7Uzdmj+k14iHMYD2gf/GNpxo+\
                                       44yIWkAxRnUw45tLhKc5PBSqpZPDg9R9pwU1XTFGc39WW4tc2wDPJSv0bQ01kH5ChcR4YY\
                                       pis3lrjgj2Xa168MRvUtWaIsFoDlw0Z5e6NS0fOAyzugkcSOLYJHJEI6GJ/OgSHuVc8Vwh\
                                       +l4p+/mjOAPqGGurFsEQ6E5Bcc4PZq/FQ+ldDOihZgdttItM1Szq4XLa0BTFgfw8KatiRE\
                                       mSqaVOsa9wmHvCgExadJI/hhYa6ADP0/KPFx3f0pZC2a5lR47rWQ5i+0UVodK72SPc7Ty8\
                                       EDBk0a7mqtXCDoxECL6eV5/Y7QouEN2x09kCgBqAoU9JlcaDtRDQH6HbT1DkiwJE43gVJ4\
                                       brKPX9wz5k77tDRGYJHjbzQxt2yF1IO7byffm5wgI1NWhrjUx+rNK4MWSaoG3PwJ4/MTsV\
                                       HN6kNMuq/AAxOXVWYPXpJgtyMKJMNZ6uRQvseKf4sKR1RLJ4qgDGS9+vR5W9l2KqYJ7qoh\
                                       ZjzoyRbetWquhSWFTXc5S/fHSkRrOCcocORPCS5731JUP4i2pbDz/z7r693VOhDqk1cMw2\
                                       SCgiTFRFPrGBD9vkOKkODv20nI3R9Vo1TVQit9czw92DxJdIaimnJHQjh9GBN4h1IYxTRx\
                                       6NaF9h3ColacQugH5H84gzSnmu3ZGSXMb+9HpGjmfKMJm1cs2yCM/plRR70zqun6TMRVaV\
                                       lWWbo6h9aAGN8AOHClAMDpAaU1Zn5YMqWh4NpPiuDfeSLmIjiou9rcu+f/QniAkMPzplZF\
                                       DHEjD4nRfsHdwF/0AAOmUP8ec9lLzJJ1ueanjW52q1ehlyNZ9TVK1Ybt++i99WRTkp508/\
                                       eK/Ky61Czho2J7IeC8YBfrSQBc1huQ36Au+nmKYMW8VMhFFl8pvwN0vs88A5h/pO0FqRRW\
                                       wqqPKjpzr9D8bHjAXWDOf3ekHc78ppg3WghL/jrL5/i9GYvcU6Ckv8qaJ7pg1pEWrZGXf4\
                                       3D7PDK0bsJpGuT4050MSL2fw282OVxEpzLDRBlrtcYP6Y+TDJMVmfZufvXfPPEzS3d0O1e\
                                       fBo0MMbaKGAHclxuQ/EhAYwZwV0K3R2fOt5voS48mRQlQHevT9vPyBJsT/1UGgyn6iw5Mw\
                                       YslXT49DHI4LEconw/sC+1EekQs4gHW51V3ed7LHwWciLvX5apTXj++pw9Gvx9qK98f1gS\
                                       AYAV12YLnZmlT+In8Itp8yN568ktwOU6FOLUiS/Q9bmnLg8FDvjas0QrZefvrd0plg6m4Q\
                                       HqsIhpW+yeKkUFUpYExlvg58wM4jEPVA8qnF+Rimah63nJC3dKYppNaSOeztRu5TH6s=")
                              .expect("base64 decoding failed");
            let expected = base64::decode("TwEIoPHIDkZKcS5Ry0o2/DNZTUH/SV9IBmkSDwFuhWIU+exoYD6ArrNCJie0f7q8WF\
                                           0E/7rfnPkcMbD0MRCGixndluEVri2GzT/8muctBbAfh0w2N6Ug6Q13mUK0LuCQUZZY\
                                           OYgCL8dsQ5j3k4Q1inM966T3xjT4Sot9Z3HzQeMau2NYTMqy0oks4fAacNSm2M61V0\
                                           /1u7sezAIpsGc40FY6FiFm0gYQ8wCs78gStn7hM9KLCLB36VE50v7EqpB9SfrQBQ/n\
                                           C6w+pAoGWb6TIopLnFs43QDwjN7NPZrgCwlv0aITenjAD+3jV/BEsX4KHTLPh8mxrH\
                                           dJUAGuzylOUu5f0vBs6bS0QEHS8xnidxqJyMKxXOnODqVhfOQq0Itfoe9mY5lw71TK\
                                           807MnZdgS2MMdsLP98YuQ360/IzwfPmb5cw48r6T48znzE3kyAAFAxE7aB5xxN9lUt\
                                           Kg9nqRTmY8TAh4YVPAXrarrn/1FARQ+AHb0YtWcAWmou23BpRh4zslQszfN4BalKSm\
                                           6N6jBdaJLB59jVPa7E5vVPd9bPGM4xk8eeuAKxeeNyOk7657A5ofbzH8ihejqUSSIB\
                                           ZHt7sqvhROV+D2EwmOg+kYXyBdbq++A9aFelBhBqWOitO4Y6otGuaY8jzOzRw0ofiC\
                                           aSGxVCUZ46ejGP5ft0hAXqBfn4gZB6CgVJKoK3rcmtAkJLNIjPIhqr6Bve8aL1RReg\
                                           roxPPXPpekA5vhOfQBtt0ybaJf8c1HYPfe86tTu5uQJp2vZv/jkwuX9OZMW0RtdjdC\
                                           HeW1/oYZB++stAe7QDT9ZelcM52eUpZ0+qbKZL/kbgCYG2eoVSTCmEr7pk+W/2pKy9\
                                           3j4U/+gvpBOcZf4HRyo4EFrXtQ0zlVSRstODa2feuVic6fJjY6rJIBq8LmDTy0q1OV\
                                           hPpftF68GWi0oVG1+sxN77Ng60HB4lxN+sgZwujBI1peRYA5VQ17ZBqURHMGE8nAeT\
                                           WqOQZTvPsFEMBTGcs2Yg6qoCPoANYPQdew/Uw7EpVZSX0QsCYmgruuCwTLUmFubkdQ\
                                           zPHfzOQbRcZQhSlPqr0Zb5jPzwyp42XxMmK7dwIfRjCUf00uFS4r+5Q0bKwLQX2S58\
                                           ClCe30LsHPD3NIEcBj2y0YqbidaYMN/Yapht8LZJt0zNDxieu83RUmAjA3hnpYqb1d\
                                           4Rs40mom3kJDb5tPhYUM5BrFgki5ttiC4PbJGTNAazkDwz4Lcr7rQrJa+zpdXJCSYV\
                                           8KpoxV7bbwLf15jjTuEHDLSmGfJmxq1P8ACbiKqs6AIjP2X2oSGtIURDTwQaJ8DVID\
                                           6wfQLDRY4h/e0qEBfE2UfgSjafIAKAsDhOjlBTgglkUc6w==")
                                  .expect("base64 decoding failed");
            let (plain, mime) = decrypt("\u{000000}\u{10FFFF}", &blob).expect("decrypt failed");
            assert_eq!(plain, expected);
            assert_eq!(mime, "application/octet-stream");
        }
    }
}
