# Crypt2web: encrypt your content and share it via a web page

Crypt2web encrypts your files using a password and produces web pages that can be viewed and decrypted using any modern web browser. These web pages are self-contained (no external scripts or dependencies) and make use of [WebAssembly] for fast decryption operations.

**Live examples:**
* [An encrypted HTML page](http://andreacorbellini.github.io/crypt2web/examples/page.html) (password: `apple`)
* [An encrypted picture](http://andreacorbellini.github.io/crypt2web/examples/picture.html) (password: `banana`)
* [An encrypted PDF file](http://andreacorbellini.github.io/crypt2web/examples/pdf.html) (password: `cherry`)

Crypt2web uses modern ciphers and algorithms: [ChaCha20] and [Poly1305] for encryption, and [PBKDF2] with [SHA-256] for key derivation.

[WebAssembly]: https://webassembly.org/
[ChaCha20]: https://en.wikipedia.org/wiki/ChaCha20
[Poly1305]: https://en.wikipedia.org/wiki/Poly1305
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[SHA-256]: https://en.wikipedia.org/wiki/SHA-2

## Installation

Crypt2web is 100% written in [Rust]. To build and install it, you will need [Cargo], the Rust package manager.

[Rust]: https://www.rust-lang.org/
[Cargo]: https://doc.rust-lang.org/cargo/getting-started/installation.html

1. Build the project in release mode:
   ```
   ./build.sh --release
   ```

1. (Optional) run the tests:
   ```
   cargo test --release -p crypt2web-core
   ```

1. The executable is now built in `target/release/crypt2web`. Put it in any directory in your `$PATH`, such as:
   ```
   cp target/release/crypt2web /usr/local/bin/
   ```

Crypt2web is now installed! Run `crypt2web --help` for usage information.

## Usage

To encrypt a file:
```sh
crypt2web path/to/file -o encrypted.html
```
Once your run that command, Crypt2web will prompt for your password on the terminal and encrypt your content. Now you can open the file `encrypted.html` in your browser, or upload it anywhere you want.

In order for the file to be correctly displayed by your web browser when decrypted, Crypt2web will try to infer the MIME type of your content automatically. You can see what MIME type is inferred by using the `-v` / `--verbose` option:
```sh
$ crypt2web -v path/to/image.jpg -o encrypted.html
Password:
Re-enter password:
Using MIME type: image/jpeg (detected)
```

You can also specify a custom MIME type by passing it to the `-t` / `--mime-type` option:
```sh
$ crypt2web -v path/to/image.jpg -o encrypted.html -t some/type
Password:
Re-enter password:
Using MIME type: some/type
```

If you don't want to manually input the password through the terminal, you can specify your password in a file and pass it to the `-p` / `--password-file` option:
```sh
$ echo 'my cool password' > password.txt
$ crypt2web -v path/to/file -o encrypted.html -p password.txt
```

## Password input methods

By default, when you visit the encrypted web page, there are two ways to decrypt the content:

1. Write the password in a prompt
1. Write the password in the URL fragment (the part of the URL after `#`)

For example, if you visit http://andreacorbellini.github.io/crypt2web/examples/page.html, you will be prompted for a password (`apple`). If instead you you visit http://andreacorbellini.github.io/crypt2web/examples/page.html#apple, the content will be decrypted automatically as soon as you open the web page.

Note that while supplying the password through the URL fragment is a handy way to share your content, you'll need to be careful not to copy the URL in any places where you don't want it to be seen. Also beware that crawlers and search engines may index your URL if they find it in any public place.

If you want to control what password input methods are accepted by the encrypted web page, use `-m` / `--password-methods`:
```sh
crypt2web path/to/file -o encrypted.html -m prompt          # only prompt for a password; don't use the URL fragment
crypt2web path/to/file -o encrypted.html -m fragment        # don't prompt for a password; only use the URL fragment
crypt2web path/to/file -o encrypted.html -m prompt,fragment # support both prompt and URL fragment (this is the default)
```

## License

This is free software released under the [Apache 2.0] license.

[Apache 2.0]: https://www.apache.org/licenses/LICENSE-2.0
