# Web3 Keystore

Forked from [eth-keystore-rs][] so it does not rely on the file system which makes it easier to intergrate with WASM and other code that does not want to store secrets as JSON files on disc.

A minimalist library to interact with encrypted JSON keystores as per the [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).

[![Documentation]][docs.rs]

[eth-keystore-rs]: https://github.com/roynalnaruto/eth-keystore-rs
[Documentation]: https://docs.rs/web3-keystore/badge.svg?version=0.4.1
[docs.rs]: https://docs.rs/web3-keystore/latest/web3_keystore/
