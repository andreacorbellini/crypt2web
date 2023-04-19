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
//! Crypt2web uses [ChaCha20] and [Poly1305] for encryption, and [PBKDF2] with [SHA-256] for key derivation.
//!
//! This package contains the core functionality used by both the command line client and the WebAssembly client.
//!
//! [WebAssembly]: https://webassembly.org/
//! [ChaCha20]: https://en.wikipedia.org/wiki/ChaCha20
//! [Poly1305]: https://en.wikipedia.org/wiki/Poly1305
//! [PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
//! [SHA-256]: https://en.wikipedia.org/wiki/SHA-2
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

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use chacha20poly1305::Tag;
use chacha20poly1305::aead::AeadInPlace;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::io::Read;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const CONTENT_LEN_SIZE: usize = 8;

const HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE + CONTENT_LEN_SIZE;

const PBKDF2_ROUNDS: u32 = 65536;

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
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
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
    let tag = cipher.encrypt_in_place_detached(&nonce, b"", &mut ciphertext[HEADER_SIZE..])
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
/// let encrypted = base64::decode("qdmFh7n3FU9MWtHjNi2m7HCg4ETTULm\
///                                 Z1hyRHAjINt7M0L7z+6Z8RuhjQoMGAA\
///                                 AAAAAAAGDCrclKMbJG2bXf3fLng/Q=")
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
    cipher.decrypt_in_place_detached(&nonce, b"", &mut plaintext, &tag)
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
            let blob = base64::decode("79YoeJDZDVye6zY/XZgmxX4wICmHbXwSgPVoWrxPdHrCgf7jVbbavuqMJMQAAAAAAAAAAA==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_1() {
            let blob = base64::decode("DOQtKyOnD/DuinMI8TSpKRxK6aAhpxEdr34oFP84bFv6/Nt9e2DjQGdIZA8AAAAAAAAAAA==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("s3cret", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_2() {
            let blob = base64::decode("W9nEuXBXkmXa7/x3VLtkOYQLGukwjMwnKCk71X/MzEEbPxeV0clFnwTTKQsFAAAAAAAAAK+\
                                       atDEr")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("pass", &blob).expect("decrypt failed");
            assert_eq!(plain, b"hello");
            assert_eq!(mime, "");
        }

        #[test]
        fn blob_3() {
            let blob = base64::decode("v2s+jmPl9rveRnnM2l8JDsiPeU663syzgbfsA4izeFWn+P4Bfuy+1KVI2mAAAAAAAAAAAH\
                                       1KtJSCmzXlXw==")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("word", &blob).expect("decrypt failed");
            assert_eq!(plain, b"");
            assert_eq!(mime, "mime/type");
        }

        #[test]
        fn blob_4() {
            let blob = base64::decode("SjAKBzic/Jd3P4j7iN/RDDpfOPqrri+lQLdgNLaKIruh0x37zi0CKtJ85o0nAAAAAAAAAE\
                                       6WDfRzse19lCn8YFaVEO+uNYBMlY9AYj/hhJvug4KgvbwS7BFrrUknwE8BsaktORc=")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("🍕🍨🍉", &blob).expect("decrypt failed");
            assert_eq!(plain[..], b"This is protected by a Unicode password"[..]);
            assert_eq!(mime, "text/plain");
        }

        #[test]
        fn blob_5() {
            let blob = base64::decode("0YkcBHYlmlZqTncti7j/9TySdeHUPTiodaB14VVPbnn7MixaBpnWRz7cYo0AAQAAAAAAAB\
                                       8ORTPv1/qZTRE/XzYdZjGp3JmArvYr6wCmWXhrfKMKCTK0Itq6rDifT9prhfnxig5+MHo4\
                                       PJQOGc8sCVKogyafWTGm5bG/kYf586vdNPoadQlpa/EN0LYRuGOZ0uljvF2ptMBxjwS2Or\
                                       q3dSfVCJUgyNH1bhN2coISqreB03YAllxpSMiMwzjqBL8x0B7oBH+gnwAlaCIUlrjBpoOs\
                                       kULgVl+Dl7pl7EzhtQN8XZwQP3aUNQvSFtQLbuIO5LNd7Q5yrP/dZH5a5fVZEQtC3SwlMQ\
                                       5iW1BP+rNhuDMhfaEazgn0AZZFNsES73+rvA8VX9iSuYVJa3ptftgXU900TLRR3R5xz/sc\
                                       6aI=")
                              .expect("base64 decoding failed");
            let (plain, mime) = decrypt("Some Password", &blob).expect("decrypt failed");
            assert_eq!(plain, (0..=std::u8::MAX).collect::<Vec<u8>>());
            assert_eq!(mime, "Some Mime");
        }

        #[test]
        fn blob_6() {
            let blob = base64::decode("oC4JKUIFjsJHfWgl//3JaB2fXjKRmUT/ZowRNBasc2/nYFjSXV0kU8O3+2kABAAAAAAAAF\
                                       MK/JqB56+7x4gu8jpotHgV/9KJcI9ZxCM07ZDrImI8W/esxU0JqVzF9f2QoiVAIwCTU81s\
                                       Q+oq+9tBE/gAexsrux7A0Iq74NHxM/hXf3vKyARbhdBIi28dxdxjmNU2SfU3FqEhnp9+l2\
                                       AsEXFWzLfDxiOKFy7QOvu6UA6kqwaIFioWFNRu2HNwxCdP8u5ZbLa/XKEU/5ifvSSz3q9J\
                                       EN+ruLIz6MaMcV6BipAHZIHzJ1wmfxZ2kl1srmX90QG+FlVFRVFQ+HHWnhTkNGeU4hpzDi\
                                       B+s+ZCjk5dqd+K5FNLKzp/1isGmxn4Ohor1+jOpqqE6PAKTbc1PGfgewpDKvTEKsPlZRlR\
                                       2Vy8+YTeZajc9uQhEQ1/WV4BxFwVib0yOqogsVtQ5E1fmdyM9cPT2z+vwRLM5KOpWWfmYD\
                                       nbOz/vynSLu639EvG2pjQATpD13tsYcZTyv1Tg4gw5ONFPtnfHbDFaWIRB4fG4NFpku4UZ\
                                       gZzOD65noobfPqdGV4COA6gv/2R98XN6w8VQIuwkVtN1Lrwdv/5rBaQZHGR6/GfdpkDf67\
                                       VKCQRX6pgtfK3UEK161DgjvIr+LSILIZPQlsvN5ZGd1EOFVh9R15EO2hocqOG2YgnyvB5y\
                                       BTjflEUbuH6DM3AZ38ROA8ySwGXuV4UwhXsGAPYFDRi3y0chcR+a5MRHMDm6SpzTV1uFH5\
                                       Zzsatz907N4YG5PG+72CQYVOfGmd1kKitTmBL46iW8cS69LXPXe9N541VXVX5ddCg/Ifcv\
                                       26JbtN8ncCsa1Jifzkq9GQipHUONhcHbqKtmGa7bFRy1XI2qP6x0iQR2SIEH5kFKcoyeaD\
                                       hd9pfEUL9sZfc2c+egSrcZPxq8V0+YCnY/o5pKu0O3H8QfMtPzUdUqp2FPZo5xPvtFSNx6\
                                       BT+diQeeKFuYNxJeCQsXx9k7Dbt+8qcVzOgKQnq5SjPIjZmii140PaZDYwMG6lTtFWavuM\
                                       FyJ3WFuTVWc5EH0cVk+TeLa8btTR1zgL0WBoQR/rqpnqhPrmdTHELob5UJ3r9GTgk0rWo7\
                                       QMj++1NJkMTqypFQs0Rj9FNtpdpnudReFzXARLTTqdOJIfQiFOf7EF0Jjt3+3xTHbk051K\
                                       Xrs8JE0oXUi7v+hpH0638Jytn3USzGMlE5ZjXCwtqKjfNON+8ZlnQqAuwPGV4SdhwpNXDv\
                                       kC/X4qzjBueaEwUWFxaffz3C2N1AYJsIYHRjn4Dg+FfMfqFHY3lbaJPzSrtn+Bw1yvuTHH\
                                       lhLlD10+ynhZ/ElAlpPZqtoAVo1qDiocgiiFjxgslt1jHCfT2dWL3eS8I3G1DLJejRWSL7\
                                       GyOo4zkz2rmL4xaT+HnribBjvZ641stJDZrTJTYZRiAaFf9MPknchG1VAFi8pc2E/bE=")
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
