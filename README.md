# ERC-6900 Ref Implementation

Reference implementation for [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900). It is an early draft implementation.

The implementation includes an upgradable modular account with two plugins (`SingleOwnerPlugin` and `TokenReceiverPlugin`). It is compliant with ERC-6900 with the latest updates.

## Caveat

- **_Not audited and should not be used in production_**.
- Not optimized in both deployments and execution.
- Lack support for easy account states building. It is possible off-chain, but not easy.

## Development

Anyone is welcome to submit feedback and/or PRs to improve code or add Plugins.

### Build

```bash
forge build

# or use the lite profile to reduce compilation time
FOUNDRY_PROFILE=lite forge build
```

### Test

```bash
forge test -vvv

# or use the lite profile to reduce compilation time
FOUNDRY_PROFILE=lite forge test -vvv
```
