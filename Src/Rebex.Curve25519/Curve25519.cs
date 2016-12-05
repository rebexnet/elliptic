using System;

namespace Rebex.Security.Cryptography
{
	/// <summary>
	/// Elliptic curve Curve25519 with Diffie Hellman key exchange scheme.
	/// </summary>
	public class Curve25519
	{
		/// <summary>
		/// Elliptic curve Curve25519 with Diffie Hellman key exchange scheme.
		/// </summary>
		public const string Curve25519Sha256 = "curve25519-sha256";

		/// <summary>
		/// Creates a new instance of <see cref="Curve25519"/> class.
		/// </summary>
		/// <param name="algorithmName">Algorithm name. Only <see cref="Curve25519Sha256"/> is supported.</param>
		public static Curve25519 Create(string algorithmName)
		{
			if (Curve25519Sha256 == algorithmName)
				return new Curve25519();

			return null;
		}

		private byte[] _privateKey;

		/// <summary>
		/// Gets algorithm name.
		/// </summary>
		public string Name
		{
			get { return Curve25519Sha256; }
		}

		private void EnsurePrivateKey()
		{
			if (_privateKey == null)
				_privateKey = Elliptic.Curve25519.CreateRandomPrivateKey();
		}
		
		/// <summary>
		/// Returns public key.
		/// </summary>
		public byte[] GetPublicKey()
		{
			EnsurePrivateKey();
			return Elliptic.Curve25519.GetPublicKey(_privateKey);
		}

		/// <summary>
		/// Returns private key.
		/// </summary>
		public byte[] GetPrivateKey()
		{
			EnsurePrivateKey();
			return (byte[])_privateKey.Clone();
		}

		/// <summary>
		/// Initializes the algorithm from public key.
		/// </summary>
		public void FromPublicKey(byte[] publicKey)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		/// Initializes the algorithm from private key.
		/// </summary>
		public void FromPrivateKey(byte[] privateKey)
		{
			if (privateKey == null)
				throw new ArgumentNullException("privateKey");

			_privateKey = (byte[])privateKey.Clone();
		}

		/// <summary>
		/// Returns shared secret for other party's public key and own private key.
		/// </summary>
		public byte[] GetSharedSecret(byte[] otherPublicKey)
		{
			if (otherPublicKey == null)
				throw new ArgumentNullException("otherPublicKey");

			EnsurePrivateKey();
			return Elliptic.Curve25519.GetSharedSecret(_privateKey, otherPublicKey);
		}

	}
}
