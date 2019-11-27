using System;

using Ed25519Inner = Chaos.NaCl.Ed25519;

namespace Rebex.Security.Cryptography
{
    public class Ed25519
    {
        private const string NAME = "ed25519-sha512";

        public static object Create(string name)
        {
            if (NAME.Equals(name, StringComparison.OrdinalIgnoreCase))
                return new Ed25519();
            else
                return null;
        }

        private byte[] _privateKey;
        private byte[] _publicKey;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name
        {
            get { return NAME; }
        }

        private void EnsurePrivateKey()
        {
            if (_privateKey != null)
                return;

            if (_publicKey == null)
                GenerateKeyPair();
            else
                throw new InvalidOperationException("Private key not available.");
        }

        private void EnsurePublicKey()
        {
            if (_publicKey != null)
                return;

            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            var seed = new byte[Ed25519Inner.PrivateKeySeedSizeInBytes];
#if NET_2_0 || NETCF_2_0
			var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
			rng.GetBytes(seed);
#else
			using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(seed);
            }
#endif
			Ed25519Inner.KeyPairFromSeed(out _publicKey, out _privateKey, seed);
        }

        /// <summary>
        /// Returns public key.
        /// </summary>
        public byte[] GetPublicKey()
        {
            EnsurePublicKey();
            return (byte[])_publicKey.Clone();
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
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (publicKey.Length != Ed25519Inner.PublicKeySizeInBytes)
                throw new ArgumentException("Invalid public key.");

            _publicKey = (byte[])publicKey.Clone();
            _privateKey = null;
        }

        /// <summary>
        /// Initializes the algorithm from private key seed.
        /// </summary>
        public void FromSeed(byte[] privateKeySeed)
        {
            if (privateKeySeed.Length != Ed25519Inner.PrivateKeySeedSizeInBytes)
                throw new ArgumentException("Invalid private key seed.");

            Ed25519Inner.KeyPairFromSeed(out _publicKey, out _privateKey, privateKeySeed);
        }

        /// <summary>
        /// Initializes the algorithm from private key.
        /// </summary>
        public void FromPrivateKey(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");
            if (privateKey.Length != Ed25519Inner.ExpandedPrivateKeySizeInBytes)
                throw new ArgumentException("Invalid private key.");

            var seed = new byte[Ed25519Inner.PrivateKeySeedSizeInBytes];
            Array.Copy(privateKey, 0, seed, 0, Ed25519Inner.PrivateKeySeedSizeInBytes);

            FromSeed(seed);

            for (int i = 0; i < Ed25519Inner.PublicKeySizeInBytes; i++)
            {
                if (_publicKey[i] != privateKey[Ed25519Inner.PublicKeySizeInBytes + i])
                    throw new InvalidOperationException("Mismatched public key.");
            }
        }

        /// <summary>
        /// Signs the supplied <paramref name="message"/>.
        /// </summary>
        public byte[] SignMessage(byte[] message)
        {
            if (message == null)
                throw new ArgumentNullException("message");

            EnsurePrivateKey();
            return Ed25519Inner.Sign(message, _privateKey);
        }

        /// <summary>
        /// Verifies the given signature matches the supplied message.
        /// </summary>
        public bool VerifyMessage(byte[] message, byte[] signature)
        {
            if (message == null)
                throw new ArgumentNullException("message");

            EnsurePublicKey();
            return Ed25519Inner.Verify(signature, message, _publicKey);
        }
    }
}
