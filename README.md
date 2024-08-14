# ERC-6900 Reference Implementation

Reference implementation for [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900). It is an early draft implementation.

The implementation includes an upgradable modular account with three modules (`SingleSignerValidationModule`, `TokenReceiverModule`, and `AllowlistModule`). It is compliant with ERC-6900 with the latest updates.

## Important Callouts

- **Not audited and should NOT be used in production**.
- Not optimized in both deployments and execution. We’ve explicitly removed some optimizations for reader comprehension.

## Development

Anyone is welcome to submit feedback and/or PRs to improve code.

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

## Integration testing

The reference implementation provides a sample factory and deploy script for the factory, account implementation, and the demo validation module `SingleSignerValidationModule`. This is not auditted, nor intended for production use. Limitations set by the GPL-V3 license apply.

To run this script, provide appropriate values in a `.env` file based on the `.env.example` template, then run:

```bash
forge script script/Deploy.s.sol <wallet options> -r <rpc_url> --broadcast
```

Where `<wallet_options>` specifies a way to sign the deployment transaction (see [here](https://book.getfoundry.sh/reference/forge/forge-script#wallet-options---raw)) and `<rpc_url>` specifies an RPC for the network you are deploying on.
