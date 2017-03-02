using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace Rebex.Security.Cryptography
{
	/// <summary>
	/// Elliptic curve Digital Signature Algorithm (ECDSA)
	/// </summary>
	public class EllipticCurveDsa : EllipticCurveAlgorithm
	{
		/// <summary>
		/// Initializes a new instance of EllipticCurveDsa class.
		/// </summary>
		/// <param name="oid">ASN.1 Object Identifier (OID)</param>
		/// <param name="curveName">ECC curve name</param>
		public EllipticCurveDsa(string oid, string curveName) : base(oid, curveName)
		{
		}

		/// <summary>
		/// Signs the supplied <paramref name="hash"/>.
		/// </summary>
		public byte[] SignHash(byte[] hash)
		{
			if (hash == null)
				throw new ArgumentNullException("hash");

			var signer = new DsaDigestSigner(new ECDsaSigner(), new NullDigest());
			return Sign(hash, signer);
		}

		/// <summary>
		/// Signs the supplied <paramref name="message"/>.
		/// </summary>
		public byte[] SignMessage(byte[] message)
		{
			if (message == null) throw new ArgumentNullException("message");

			var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
			return Sign(message, signer);
		}

		private byte[] Sign(byte[] data, ISigner signer)
		{
			if (data == null)
				throw new ArgumentNullException("data");

			EnsurePrivate();

			signer.Init(true, PrivateKey);
			signer.BlockUpdate(data, 0, data.Length);
			byte[] signature = signer.GenerateSignature();

			int keySize = (BitLength + 7) / 8;
			signature = DecodeSignature(signature, keySize);

			return signature;
		}

		/// <summary>
		/// Verifies the given signature matches the supplied hash.
		/// </summary>
		public bool VerifyHash(byte[] hash, byte[] signature)
		{
			if (hash == null) throw new ArgumentNullException("hash");

			var signer = new DsaDigestSigner(new ECDsaSigner(), new NullDigest());
			return Verify(hash, signature, signer);
		}

		/// <summary>
		/// Verifies the given signature matches the supplied message.
		/// </summary>
		public bool VerifyMessage(byte[] message, byte[] signature)
		{
			if (message == null) throw new ArgumentNullException("message");

			var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
			return Verify(message, signature, signer);
		}

		private bool Verify(byte[] data, byte[] signature, ISigner signer)
		{
			if (data == null) throw new ArgumentNullException("data");
			if (signature == null) throw new ArgumentNullException("signature");

			EnsurePublic();

			int keySize = (BitLength + 7)/8;
			if (signature.Length != keySize*2)
				return false;

			signature = EncodeSignature(signature, keySize);

			signer.Init(false, PublicKey);
			signer.BlockUpdate(data, 0, data.Length);
			return signer.VerifySignature(signature);
		}

		private static byte[] DecodeSignature(byte[] signature, int keySize)
		{
			var seq = (Asn1Sequence)Asn1Object.FromByteArray(signature);
			var parser = seq.Parser;
			var ri = (DerInteger)parser.ReadObject();
			var si = (DerInteger)parser.ReadObject();
			byte[] r = ri.Value.ToByteArrayUnsigned();
			byte[] s = si.Value.ToByteArrayUnsigned();

			if (r.Length > keySize || s.Length > keySize)
				throw new InvalidOperationException("Invalid ECDSA signature.");

			signature = new byte[keySize * 2];
			r.CopyTo(signature, keySize - r.Length);
			s.CopyTo(signature, keySize * 2 - s.Length);
			return signature;
		}

		private static byte[] EncodeSignature(byte[] signature, int keySize)
		{
			byte[] r = new byte[keySize];
			byte[] s = new byte[keySize];
			Array.Copy(signature, 0, r, 0, keySize);
			Array.Copy(signature, keySize, s, 0, keySize);

			var ri = new DerInteger(new BigInteger(1, r));
			var si = new DerInteger(new BigInteger(1, s));
			var seq = new DerSequence(ri, si);
			return seq.GetDerEncoded();
		}
	}
}
