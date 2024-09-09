using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;

namespace Rebex.Security.Cryptography
{
	/// <summary>
	/// Base class for Bouncy Castle elliptic algorithms.
	/// </summary>
	public class EllipticCurveAlgorithm
	{
		#region consts
		/// <summary>
		/// ECDSA with 256-bit ECC Brainpool curve brainpoolP256r1.
		/// </summary>
		public const string EcDsaSha2BrainpoolP256R1 = "ecdsa-sha2-brainpoolp256r1";

		/// <summary>
		/// ECDSA with 384-bit ECC Brainpool curve brainpoolP384r1.
		/// </summary>
		public const string EcDsaSha2BrainpoolP384R1 = "ecdsa-sha2-brainpoolp384r1";

		/// <summary>
		/// ECDSA with 512-bit ECC Brainpool curve brainpoolP512r1.
		/// </summary>
		public const string EcDsaSha2BrainpoolP512R1 = "ecdsa-sha2-brainpoolp512r1";

		/// <summary>
		/// ECDSA with 256-bit NIST curve P-256.
		/// </summary>
		public const string EcDsaSha2Nistp256 = "ecdsa-sha2-nistp256";

		/// <summary>
		/// ECDSA with 384-bit NIST curve P-384.
		/// </summary>
		public const string EcDsaSha2Nistp384 = "ecdsa-sha2-nistp384";

		/// <summary>
		/// ECDSA with 521-bit NIST curve P-521.
		/// </summary>
		public const string EcDsaSha2Nistp521 = "ecdsa-sha2-nistp521";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 256-bit ECC Brainpool curve brainpoolP256r1.
		/// </summary>
		public const string EcdhSha2BrainpoolP256R1 = "ecdh-sha2-brainpoolp256r1";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 384-bit ECC Brainpool curve brainpoolP384r1.
		/// </summary>
		public const string EcdhSha2BrainpoolP384R1 = "ecdh-sha2-brainpoolp384r1";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 512-bit ECC Brainpool curve brainpoolP512r1.
		/// </summary>
		public const string EcdhSha2BrainpoolP512R1 = "ecdh-sha2-brainpoolp512r1";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 256-bit NIST curve P-256.
		/// </summary>
		public const string EcdhSha2Nistp256 = "ecdh-sha2-nistp256";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 384-bit NIST curve P-384.
		/// </summary>
		public const string EcdhSha2Nistp384 = "ecdh-sha2-nistp384";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman with 521-bit NIST curve P-521.
		/// </summary>
		public const string EcdhSha2Nistp521 = "ecdh-sha2-nistp521";
		#endregion

		private readonly ECKeyParametersExt _info;

		#region ctor and factory methods
		/// <summary>
		/// Initializes a new instance of <see cref="EllipticCurveAlgorithm"/> class.
		/// </summary>
		/// <param name="oid">Object Identifier of the curve</param>
		/// <param name="curveName">Curve name</param>
		protected EllipticCurveAlgorithm(string oid, string curveName)
		{
			if (curveName == null) throw new ArgumentNullException("curveName");
			if (oid == null) throw new ArgumentNullException("oid");

			CurveName = curveName;

			X9ECParameters x9 = CustomNamedCurves.GetByName(oid);
			if (x9 != null)
			{
				_info = new ECKeyParametersExt(x9);
			}
			else
			{
				DerObjectIdentifier oidDer;
				try
				{
					oidDer = new DerObjectIdentifier(oid);
				}
				catch (FormatException)
				{
					throw new InvalidOperationException("Unknown curve: '" + oid + "'.");
				}

				_info = new ECKeyParametersExt(oidDer);
			}

			BitLength = String.Equals(oid, "curve25519", StringComparison.OrdinalIgnoreCase) 
				? 256 
				: _info.Parameters.N.BitLength;

			if (BitLength <= 256)
				SignatureAlgorithm = "SHA-256withECDSA";
			else if (BitLength <= 384)
				SignatureAlgorithm = "SHA-384withECDSA";
			else
				SignatureAlgorithm = "SHA-512withECDSA";
		}

		private EllipticCurveAlgorithm(EllipticCurveAlgorithm obj)
		{
			_info = obj._info;
			BitLength = obj.BitLength;
			SignatureAlgorithm = obj.SignatureAlgorithm;
		}

		/// <summary>
		/// Returns a new instance of <see cref="EllipticCurveAlgorithm"/> class or <c>null</c> if the algorithm name is not supported.
		/// </summary>
		public static EllipticCurveAlgorithm Create(string algName)
		{
			switch (algName.ToLower())
			{
				case EcDsaSha2BrainpoolP256R1: return new EllipticCurveDsa("1.3.36.3.3.2.8.1.1.7", "brainpoolp256r1");
				case EcDsaSha2BrainpoolP384R1: return new EllipticCurveDsa("1.3.36.3.3.2.8.1.1.11", "brainpoolp384r1");
				case EcDsaSha2BrainpoolP512R1: return new EllipticCurveDsa("1.3.36.3.3.2.8.1.1.13", "brainpoolp512r1");
				case EcDsaSha2Nistp256: return new EllipticCurveDsa("1.2.840.10045.3.1.7", "nistp256");
				case EcDsaSha2Nistp384: return new EllipticCurveDsa("1.3.132.0.34", "nistp384");
				case EcDsaSha2Nistp521: return new EllipticCurveDsa("1.3.132.0.35", "nistp521");
				case EcdhSha2BrainpoolP256R1: return new EllipticCurveDiffieHellman("1.3.36.3.3.2.8.1.1.7", "brainpoolp256r1");
				case EcdhSha2BrainpoolP384R1: return new EllipticCurveDiffieHellman("1.3.36.3.3.2.8.1.1.11", "brainpoolp384r1");
				case EcdhSha2BrainpoolP512R1: return new EllipticCurveDiffieHellman("1.3.36.3.3.2.8.1.1.13", "brainpoolp512r1");
				case EcdhSha2Nistp256: return new EllipticCurveDiffieHellman("1.2.840.10045.3.1.7", "nistp256");
				case EcdhSha2Nistp384: return new EllipticCurveDiffieHellman("1.3.132.0.34", "nistp384");
				case EcdhSha2Nistp521: return new EllipticCurveDiffieHellman("1.3.132.0.35", "nistp521");
				default:
					return null;
			}
		}
		#endregion

		internal int BitLength { get; private set; }
		
		/// <summary>
		/// Gets curve name
		/// </summary>
		public string CurveName { get; private set; }

		/// <summary>
		/// Gets the name of the algorithm. This name is internally used by Rebex libraries. 
		/// </summary>
		public virtual string Name
		{
			get { return CurveName; }
		}

		internal ECPrivateKeyParameters PrivateKey { get; private set; }

		internal ECPublicKeyParameters PublicKey { get; private set; }

		internal string SignatureAlgorithm { get; private set; }

		internal EllipticCurveAlgorithm CreateBase()
		{
			return new EllipticCurveAlgorithm(this);
		}

		internal void EnsurePublic()
		{
			if (PublicKey != null)
				return;
			
			var generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
			generator.Init(new ECKeyGenerationParameters(_info.Parameters, new SecureRandom()));
			var key = generator.GenerateKeyPair();
			PublicKey = (ECPublicKeyParameters)key.Public;
			PrivateKey = (ECPrivateKeyParameters)key.Private;
		}

		internal void EnsurePrivate()
		{
			EnsurePublic();
			
			if (PrivateKey == null)
				throw new InvalidOperationException("Private key not available.");
		}

		/// <summary>
		/// Initializes the algorithm from public key.
		/// </summary>
		/// <remarks>
		/// byte[] X
		/// byte[] Y
		/// </remarks>
		public void FromPublicKey(byte[] publicKey)
		{
			if (publicKey == null)
				throw new ArgumentNullException("publicKey");

			if (publicKey.Length == 0)
				throw new InvalidOperationException("Invalid EC key.");

			if (publicKey[0] != 4)
				throw new InvalidOperationException("EC point compression not supported.");

			if ((publicKey.Length & 1) != 1)
				throw new InvalidOperationException("Unsupported EC key.");

			int keySize = publicKey.Length / 2;
			if ((BitLength + 7) / 8 != keySize)
				throw new InvalidOperationException("Unexpected EC key bit length.");

			byte[] X = new byte[keySize];
			byte[] Y = new byte[keySize];
			Array.Copy(publicKey, 1, X, 0, keySize);
			Array.Copy(publicKey, 1 + keySize, Y, 0, keySize);

			var curve = _info.Parameters.Curve;
			ECFieldElement x = curve.FromBigInteger(new BigInteger(1, X));
			ECFieldElement y = curve.FromBigInteger(new BigInteger(1, Y));
			ECPoint q2 = new FpPoint(curve, x, y);

			PublicKey = new ECPublicKeyParameters(_info.AlgorithmName, q2, _info.Parameters);
			PrivateKey = null;
		}

		/// <summary>
		/// Initializes the elliptic curve algorithm from private key. 
		/// </summary>
		public void FromPrivateKey(byte[] privateKey)
		{
			if (privateKey == null)
				throw new ArgumentNullException("privateKey");

			if (privateKey.Length == 0)
				throw new InvalidOperationException("Invalid EC key.");

			var seq = Asn1Object.FromByteArray(privateKey) as Asn1Sequence;
			if (seq == null)
				throw new InvalidOperationException("Unsupported EC key.");

			var ecpk = ECPrivateKeyStructure.GetInstance(seq);
			BigInteger d = ecpk.GetKey();

			FromPublicKey(ecpk.GetPublicKey().GetBytes());
			PrivateKey = new ECPrivateKeyParameters(_info.AlgorithmName, d, _info.Parameters);
		}

		/// <summary>
		/// Returns the private key.
		/// </summary>
		/// <returns></returns>
		public byte[] GetPrivateKey()
		{
			EnsurePrivate();

			var publicKey = new DerBitString(PublicKey.Q.GetEncoded());
			var ecpk = new ECPrivateKeyStructure(BitLength, PrivateKey.D, publicKey, PublicKey.PublicKeyParamSet);
			return ecpk.GetDerEncoded();
		}

		/// <summary>
		/// Returns the public key.
		/// </summary>
		/// <returns></returns>
		public byte[] GetPublicKey()
		{
			EnsurePublic();

			return PublicKey.Q.GetEncoded();
		}
	}

}
