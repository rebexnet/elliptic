## Introduction

Elliptic Curve Cryptography (ECC) is an attractive alternative to classic public-key algorithms based on modular exponentiation. Compared to the algortihms such as RSA, DSA or Diffie-Hellman, elliptic curve cryptography offers equivalent security with smaller key sizes.

Unfortunately, built-in support for ECC algorithms in Microsoft Windows and .NET Framework is very limited. The only supported ECC algorithms are Elliptic Curve DSA (ECDSA) and Elliptic Curve Diffie Hellman (ECDH) based on NIST P-256, P-384 and P-521 curves. Additionally, MS CNG API is rather limited and its implementation of Elliptic Curve Diffie Hellman is not quite suitable for SSH due to lack of support for compatible shared secret padding methods. On top of this, there is a bug in MS CNG implementation of ECDH related to handling of shared secret padding, which can occasionally lead to TLS/SSL negotiation failures.

## Supported algorithms

Due to these limitations mentioned above, Rebex components only support some algorithms out-of-the-box, and only on some platforms. However, additional algorithms can easily be enabled using an external plugin. 

See [Rebex Labs](http://labs.rebex.net/curves) for complete list of supported algorithms and platforms.

## Using external plugins to enable ECC

The packages can be installed using [NuGet](https://www.nuget.org/profiles/rebex) package manager:
```powershell
PM> Install-Package Rebex.Elliptic.Ed25519
PM> Install-Package Rebex.Elliptic.Curve25519
PM> Install-Package Rebex.Elliptic.Castle
```

To enable the abovementioned plugins, add the following code to register them:

```csharp
// import NISTP and Brainpool curves
AsymmetricKeyAlgorithm.Register(EllipticCurveAlgorithm.Create);

// import Curve25519
AsymmetricKeyAlgorithm.Register(Curve25519.Create);

// import Ed25519
AsymmetricKeyAlgorithm.Register(Ed25519.Create);
```
