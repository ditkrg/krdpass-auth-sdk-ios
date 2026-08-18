# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | yes |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Email **security@pass.krd** instead, and include:

1. **Description**: a clear description of the vulnerability
2. **Steps to reproduce**: detailed steps to reproduce the issue
3. **Impact**: what an attacker could achieve by exploiting it
4. **Environment**: SDK name/version, platform version, device information
5. **Proof of concept**: if possible

### Our commitment

- We will acknowledge receipt of your report within 48 hours.
- We will provide a more detailed response within 7 days indicating our next steps.
- We will keep you informed about our progress throughout the process.
- We will credit you (with your permission) when the vulnerability is disclosed.

## A note on one deliberate choice

**The SDK does not pin the TLS certificate of `account.id.krd`.** Every network call the
SDK makes goes through `URLSession(configuration: .ephemeral)` with no
`URLSessionDelegate`, so server trust is evaluated by the system trust store and App
Transport Security, and nothing else. That is deliberate, not an oversight.

A pin outlives any release we can ship. An SDK is embedded in apps we do not control and
cannot update, so a pinned certificate that is rotated or expires bricks sign-in for every
installed copy until each publisher ships a new build through App Review. That is an
offline failure mode we would be adding, not removing.

What is enforced instead: the JWKS endpoint, which is the root of trust for ID token
signature verification, must be HTTPS or verification fails closed, so signing keys cannot
be swapped over a downgraded transport.

If your own threat model requires pinning, add it in your app rather than asking us to add
it in the SDK: build a `URLSession` whose delegate pins in
`urlSession(_:didReceive:completionHandler:)`, hand it to
`KrdpassAuth.initialize(_:urlSession:)`, and own the rotation schedule that comes with it.
Your app ships on your release cadence.

## Full Security Policy

The complete KRDPASS security policy, including the security model for the
app-to-app authorization flow and redirect validation, is maintained in the
samples repository:
[`docs/SECURITY.md`](https://github.com/ditkrg/krdpass-auth-samples/blob/main/docs/SECURITY.md).
