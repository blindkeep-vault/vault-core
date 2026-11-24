# RSA-OAEP test fixtures

Test-only keys and vectors for `src/rsa_oaep.rs` (#297). The private keys
exist only to stand in for a KMS in tests; nothing outside `#[cfg(test)]`
reads them.

| File | Contents |
|------|----------|
| `rsa{2048,3072,4096}.spki.der` | Public keys, SubjectPublicKeyInfo DER. 2048 is the rejection case. |
| `rsa{3072,4096}.pk8.der`, `rsa3072_other.pk8.der` | Matching private keys, PKCS#8 DER. `_other` is the wrong-recipient case. |
| `item_key.bin` | 32-byte item key `00 01 02 … 1f`. |
| `wrapped_openssl_3072.bin` | `item_key.bin` wrapped to `rsa3072` by OpenSSL. |
| `wrapped_webcrypto_3072.bin` | `item_key.bin` wrapped to `rsa3072` by Web Crypto (Node). |

To regenerate:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -outform DER \
  | openssl pkcs8 -topk8 -nocrypt -inform DER -outform DER -out rsa3072.pk8.der
openssl pkey -inform DER -in rsa3072.pk8.der -pubout -outform DER -out rsa3072.spki.der

openssl pkeyutl -encrypt -pubin -keyform DER -inkey rsa3072.spki.der \
  -in item_key.bin -out wrapped_openssl_3072.bin \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256

node webcrypto_wrap.mjs rsa3072.spki.der item_key.bin wrapped_webcrypto_3072.bin
```

The vectors are randomized, so regenerating them changes the bytes; the tests
only check that they open to `item_key.bin`.
