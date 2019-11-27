using System;
using System.Collections.Generic;
using System.Text;
using Chaos.NaCl.Internal.Ed25519Ref10;

namespace Chaos.NaCl
{
	internal class MontgomeryCurve25519
	{
		internal static void EdwardsToMontgomeryX(out FieldElement montgomeryX, ref FieldElement edwardsY, ref FieldElement edwardsZ)
		{
			throw new NotSupportedException("Key exchange is not supported yet.");
		}

		internal static void KeyExchangeOutputHashNaCl(byte[] array, int offset)
		{
			throw new NotSupportedException("Key exchange is not supported yet.");
		}
	}
}
