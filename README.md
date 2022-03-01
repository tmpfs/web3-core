# Web3 Core

Collection of crates designed for a minimal suite of functionality appropriate for creating a web3 wallet.

Design goals are first-class support for Webassembly and support for MPC using [multi-party-ecdsa][].

Derived from work on [ethers][], [web3][] and [eth-keystore][].

## Tests

To run the tests first start `ganache` using a specific mnemonic:

```
make test-server
```

Then ensure the test MPC account has some funds:

```
make fund-mpc-account
```

Then you can run the test suite:

```
cargo test --all
```

[ethers]: https://github.com/gakonst/ethers-rs
[web3]: https://github.com/tomusdrw/rust-web3
[eth-keystore]: https://github.com/roynalnaruto/eth-keystore-rs
[multi-party-ecdsa]: https://github.com/ZenGo-X/multi-party-ecdsa
