# Commercial License for IronEvidence

Copyright (C) 2026 NERVOSYS. All rights reserved.

## Dual licensing

IronEvidence (the crate `ironevidence`) is available under two licences.

### 1. GNU Affero General Public License v3 (AGPL-3.0-or-later)

The default licence is the **GNU Affero General Public License v3**. Under it:

- You may use, copy, modify and distribute the software.
- If you modify it and make it available over a network, for example as a
  service, you **must** make the complete source of your modified version
  available to that service's users.
- Derivative works must also be licensed under the AGPL v3.
- Full text: [LICENSE](LICENSE).

Linking IronEvidence into a service that produces compliance evidence makes
that service a derivative work, and the AGPL's source-disclosure obligation
applies to it. The documents IronEvidence writes are data, not derivative
works of it.

### 2. Commercial licence

A **commercial licence** is available from NERVOSYS if the AGPL does not fit
your use. For example, if you want to:

- integrate IronEvidence into proprietary or closed-source software;
- embed it in a shipped product or compliance tool;
- distribute it without disclosing your source code;
- run it in a hosted service without AGPL obligations;
- receive dedicated support, warranty or indemnification.

**IronCrypto is licensed separately.** IronEvidence reads JSON through
[IronCrypto](https://github.com/nervosys/IronCrypto)'s `ic-json`, which is
also AGPL-3.0-or-later with its own commercial option. Proprietary use of
IronEvidence therefore also needs a commercial IronCrypto licence. Ask for
both together.

## Obtaining a commercial licence

- **Email**: licensing@nervosys.ai
- **GitHub**: [github.com/nervosys](https://github.com/nervosys)

## What a licence does not cover

Neither licence makes a claim about assurance:

- **No FIPS validation.** Neither IronEvidence nor IronCrypto holds a CMVP
  certificate, and a commercial licence does not confer one.
- **No independent review.** See [SECURITY.md](SECURITY.md).
- **Warranty.** The AGPL version comes without warranty, as the licence
  states. Any warranty or indemnification is set out in the commercial
  agreement, not here.
- **No compliance finding.** IronEvidence records what a component's
  maintainers state about controls. Neither licence makes its output an
  assessment, an authorization or a certification.

## Contributor Licence Agreement

Contributors agree to the [Contributor License Agreement](CLA.md) before
their contributions are accepted. It lets contributions be distributed under
both the AGPL v3 and the commercial licence. See [CONTRIBUTING.md](CONTRIBUTING.md).
