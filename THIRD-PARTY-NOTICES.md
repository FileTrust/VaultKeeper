# Vaultkeeper third-party credits

FileTrust code retains the existing FSL-1.1-ALv2 terms in LICENSE. Third-party
software retains its own license and copyright notices.

The runtime uses Consensys gnark and gnark-crypto for BN254/Groth16 proving,
Go Ethereum for EVM integration, and go-libp2p/multiaddr for peer networking.
Exact module versions and transitive dependencies are recorded in
runtime/code/go.mod, runtime/code/go.sum, runtime/prover/go.mod and go.sum.
Their corresponding upstream source is available at:

* https://github.com/Consensys/gnark/tree/v0.14.0
* https://github.com/Consensys/gnark-crypto/tree/v0.19.1 (prover)
* https://github.com/Consensys/gnark-crypto/tree/v0.18.1 (node)
* https://github.com/ethereum/go-ethereum/tree/v1.17.2
* https://github.com/libp2p/go-libp2p/tree/v0.48.0

The complete FileTrust runtime source used for local compilation is
included in runtime/. Upstream library source, notices and licensing conditions
remain applicable, including Go Ethereum's applicable LGPL/GPL component terms.
Before public binary redistribution, review the complete linked module license
set and corresponding-source/relinking requirements; this private test release
does not certify a completed redistribution audit.

Python dependencies are installed from PyPI with their package metadata:
web3.py and eth-account (MIT); cryptography (Apache-2.0 or BSD-3-Clause), Requests
(Apache-2.0), TUF (Apache-2.0 or MIT), and securesystemslib (MIT). Their retained
upstream texts are in licenses/. Transitive packages retain their own licenses.

Vaultkeeper does not install or invoke ZoKrates. Its setup files are existing
public gnark proving parameters, never wallet keys, setup randomness or stored
user pieces. Original verifier-generation/factory tools remain in private VK.

The installer can download the official Go 1.26.10 SDK. Its BSD-style license and
third-party notices remain in the SDK archive and extracted toolchain. Compiler
and module caches are build prerequisites, not generated cryptographic setup.
