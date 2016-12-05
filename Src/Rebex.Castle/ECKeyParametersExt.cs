using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace Rebex.Security.Cryptography
{
	internal class ECKeyParametersExt : ECKeyParameters
	{
		public ECKeyParametersExt(DerObjectIdentifier curve)
			: base("ECDH", false, curve)
		{
			XParameters = new X962Parameters(curve);
		}

		public ECKeyParametersExt(X9ECParameters x9)
			: base("ECDH", false, ToParameters(x9))
		{
			XParameters = new X962Parameters(x9);
		}

		public X962Parameters XParameters { get; private set; }

		private static ECDomainParameters ToParameters(X9ECParameters x9)
		{
			return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
		}
	}
}