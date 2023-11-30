# ERC-6900 Reference Implementation

Reference implementation for [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900). It is an early draft implementation.

The implementation includes an upgradable modular account with two plugins (`SingleOwnerPlugin` and `TokenReceiverPlugin`). It is compliant with ERC-6900 with the latest updates.

## Important Callouts

- **Not audited and should NOT be used in production**.
- Not optimized in both deployments and execution. We’ve explicitly removed some optimizations for reader comprehension.

## Development

Anyone is welcome to submit feedback and/or PRs to improve code or add Plugins.

### Testing

The default Foundry profile can be used to compile (without IR) and test the entire project. The default profile should be used when generating coverage and debugging.

```bash
forge build
forge test -vvv
```

Since IR compilation generates different bytecode, it's useful to test against the contracts compiled via IR. Since compiling the entire project (including the test suite) takes a long time, special profiles can be used to precompile just the source contracts, and have the tests deploy the relevant contracts using those artifacts.

```bash
FOUNDRY_PROFILE=optimized-build forge build
FOUNDRY_PROFILE=optimized-test forge test -vvv
```
