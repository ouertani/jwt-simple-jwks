# Changelog
* 0.3.0
  * **Breaking change**: Use [jwt-simple](https://crates.io/crates/jwt-simple)
* 0.2.0
  * **Breaking Change**: Support for async/await (Thanks to [Genna Wingert](htps://github.com/wingertge))
* 0.1.8
  * Fixed issued https://github.com/jfbilodeau/jwks-client/issues/1 (Thanks to [Tim Schuster](https://github.com/tscs37) for reporting and assisting)
* 0.1.7
  * Updated dependencies
* 0.1.6
  * Added `key_set::KeyStore::should_refresh()` to test if keys should be refreshed
  * Added `key_set::KeyStore::refresh_interval` to determine how early keys should be refreshed before they expire
  * Some more documentation
* 0.1.5:
  * Added `readme = "README.md"` to `Cargo.toml`
* 0.1.4:
  * Updated documentation--specifically how to use JWKS-Client with Rocket
  * Added the ability to determine if keys should be refreshed from the `KeyStore`
  * Fixed example on this page--they are now directly from `./examples/*`
* 0.1.3:
  * Change the license to be MIT/Apache
  * Moved demos into `./example`
  * Added the ability to verify if keys need to be refreshed in the keystore based on the cache-control header
* 0.1.2:
  * Rename module `jwks` to `keyset`
  * Renamed struct `Jwks` to `KeyStore`
  * Expanded documentation a bit
  * Fixed some demos
* 0.1.1: Original version
