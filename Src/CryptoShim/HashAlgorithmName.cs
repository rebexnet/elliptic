using System;

namespace System.Security.Cryptography
{
	public struct HashAlgorithmName
	{
		public HashAlgorithmName(string name)
		{
		}

		public static HashAlgorithmName SHA512
		{
			get
			{
				return new HashAlgorithmName("SHA512");
			}
		}
	}
}
