## Introduction

Elliptic Curve Cryptography (ECC) is an attractive alternative to classic public-key algorithms based on modular exponentiation. Compared to the algortihms such as RSA, DSA or Diffie-Hellman, elliptic curve cryptography offers equivalent security with smaller key sizes.

Unfortunately, built-in support for ECC algorithms in Microsoft Windows and .NET Framework is very limited. The only supported ECC algorithms are Elliptic Curve DSA (ECDSA) and Elliptic Curve Diffie Hellman (ECDH) based on NIST P-256, P-384 and P-521 curves. Additionally, MS CNG API is rather limited and its implementation of Elliptic Curve Diffie Hellman is not quite suitable for SSH due to lack of support for compatible shared secret padding methods. On top of this, there is a bug in MS CNG implementation of ECDH related to handling of shared secret padding, which can occasionally lead to TLS/SSL negotiation failures.

To work around these limitations, we provide a set of assemblies that provide a simple-to-use API on top of thrid-party ECC libraries. See [Rebex Labs](//labs.rebex.net/curves) for details, including a  list of supported algorithms and platforms.

## Credentials

These assemblies are based on:
- [Curve25519 library](//github.com/hanswolff/curve25519) by Hans Wolff, based on previous work by Dmitry Skiba [sahn0] and Matthijs van Duin.
- [Ed25519 library](//github.com/CodesInChaos/Chaos.NaCl) by Christian Winnerlein (CodesInChaos), based on the SUPERCOP "ref10" implementation.
- [BouncyCastle APIs](//hwww.bouncycastle.org/) by the Legion of the Bouncy Castle Inc.

## Disclaimer

Some or all of these algorithms might be susceptible to [timing attacks](https://research.kudelskisecurity.com/2017/01/16/when-constant-time-source-may-not-save-you/). ECDH key exchange in context of SSH and TLS/SSL is immune (a private key is only used once and then discarded), but we cannot wouch for ECDSA and EdDSA implementations.

## Installation

The packages can be installed using [NuGet](https://www.nuget.org/profiles/rebex) package manager:
```powershell
PM> Install-Package Rebex.Elliptic.Ed25519
PM> Install-Package Rebex.Elliptic.Curve25519
PM> Install-Package Rebex.Elliptic.Castle
```

## Usage within Rebex components

To use these assemblies as [plugins for Rebex components](//www.rebex.net/kb/elliptic-curve-plugins/), add the following code to register them:

```csharp
// import NISTP and Brainpool curves
AsymmetricKeyAlgorithm.Register(EllipticCurveAlgorithm.Create);

// import Curve25519
AsymmetricKeyAlgorithm.Register(Curve25519.Create);

// import Ed25519
AsymmetricKeyAlgorithm.Register(Ed25519.Create);
```

