using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;

namespace Rebex.Security.Cryptography
{
	/// <summary>
	/// Elliptic curve Diffie Hellman (ECDH)
	/// </summary>
	public class EllipticCurveDiffieHellman : EllipticCurveAlgorithm
	{
		/// <summary>
		/// Initializes a new instance of EllipticCurveDiffieHellman class.
		/// </summary>
		public EllipticCurveDiffieHellman(string oid, string curveName) : base(oid, curveName)
		{
		}

		/// <summary>
		/// Returns shared secret for other party's public key and own private key.
		/// </summary>
		public byte[] GetSharedSecret(byte[] otherPublicKey)
		{
			if (otherPublicKey == null)
				throw new ArgumentNullException("otherPublicKey");

			EnsurePrivate();

			var ecdh2 = CreateBase();
			ecdh2.FromPublicKey(otherPublicKey);

			var agreement = AgreementUtilities.GetBasicAgreement("ECDH");
			agreement.Init(PrivateKey);

			BigInteger sharedSecret = agreement.CalculateAgreement(ecdh2.PublicKey);
			byte[] sharedSecretBytes = sharedSecret.ToByteArray();

			return sharedSecretBytes;
		}
	}
}
