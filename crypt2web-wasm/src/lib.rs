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

#![warn(missing_debug_implementations)]
#![warn(unreachable_pub)]
#![warn(unused_qualifications)]

use js_sys::Array;
use js_sys::Uint8Array;
use std::fmt;
use wasm_bindgen::prelude::*;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn decrypt(password: &str, ciphertext: &Uint8Array) -> Result<Array, JsValue> {
    let (bytes, mime) = crypt2web_core::decrypt(password, &ciphertext.to_vec())
                                       .map_err(decrypt_error)?;
    let bytes = Uint8Array::from(bytes.as_slice());
    let arr = Array::new();
    arr.push(&bytes);
    arr.push(&JsValue::from(mime));
    Ok(arr)
}

fn decrypt_error<E: fmt::Display>(e: E) -> JsValue {
    JsValue::from(format!("{}", e))
}
