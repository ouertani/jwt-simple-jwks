# jwt-simple-jwks

[![Docs](https://docs.rs/jwt-simple-jwks/badge.svg)](https://docs.rs/jwt-simple-jwks)
[![Crates.io](https://img.shields.io/crates/v/jwt-simple-jwks.svg?maxAge=2592000)](https://crates.io/crates/jwt-simple-jwks)
[![Build Status](https://travis-ci.com/seanpianka/jwks-client.svg?branch=master)](https://travis-ci.com/seanpianka/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![License:Apache](https://img.shields.io/badge/License-Apache-yellow.svg)](https://opensource.org/licenses/Apache-2.0) ![Minimum rustc version](https://img.shields.io/badge/rustc-stable-success.svg)

jwt-simple-jwks is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.

This JWKS client is compatible only with [jwt-simple](https://crates.io/crates/jwt-simple).

## Installation

```toml
[dependencies]
jwt-simple-jwks = "0.3"
``` 

## Features

### JWKS key store
* Download key set from HTTP address
* Decode JWT tokens into header, payload and signature
* Verify token signature, expiry and not-before
* Determine when keys should be refreshed
* No panic!
  
### JWT: 
* Uses the crate [jwt-simple](https://crates.io/crates/jwt-simple) to provide the decoding features for RSA keys.

## Basic Usage

The following demonstrates how to load a set of keys from an HTTP address and verify a JWT token using those keys:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jkws_url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.8/test/test-jwks.json";

    let key_set = KeyStore::new_from(jkws_url.to_owned()).await.unwrap();

    // ...

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Serialize, Deserialize, Debug)]
    pub struct CustomClaims {
        auth_time: i64,
        name: String,
        user_id: String,
        email: String,
    }

    let validation = jwt_simple::prelude::VerificationOptions {
        allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
        ..Default::default()
    };

    match key_set.verify::<CustomClaims>(token, Some(validation)) {
        Ok(claims) => {
            println!("iss={}", claims.issuer.unwrap());
            println!("name={}", claims.custom.name);
        }
        Err(Error { msg, typ }) => {
            eprintln!("Could not verify token. Reason: {} {:?}", msg, typ);
        }
    }
    Ok(())
}
```

## Author's Note

Made with ❤️  in Rust
