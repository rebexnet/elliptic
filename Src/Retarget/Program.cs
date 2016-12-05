using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Corizer
{

	public class Program
	{
		public const string Net40 = ".NETFramework,Version=v4.0";
		public const string Standard16 = ".NETStandard,Version=v1.6";

		public static int Main(string[] args)
		{
			if (args.Length < 3 || args.Length > 4)
			{
				Console.WriteLine("Utility for retargetting some Rebex .NET 4.0 assemblies to .NET Core and .NET 2.0");
				Console.WriteLine("Warning: This is not a general purpose utility; it only supports a single Rebex assembly (Rebex.Ed25519)");
				Console.WriteLine();
				Console.WriteLine("Usage:");
				Console.WriteLine("\tretarget input_assembly output_assembly framework [keypath]");
				return 1;
			}

			string input = args[0];
			string output = args[1];
			string framework = args[2];
			string frameworkName = null;
			string keyPath = (args.Length == 4) ? args[3] : null;
			bool remap = false;
			string corlibVersion = "4.0.0.0";
			string corlibToken = "b77a5c561934e089";

			switch (framework)
			{
				case "core-1.0":
				case Standard16:
					framework = Standard16;
					remap = true;
					break;
				case "net-4.0":
				case Net40:
					framework = Net40;
					frameworkName = ".NET Framework 4";
					break;
				case "net-2.0":
					framework = null;
					corlibVersion = "2.0.0.0";
					break;
				case "netcf-2.0":
					framework = null;
					corlibVersion = "2.0.0.0";
					corlibToken = "969db8053d3322ac";
					break;
				default:
					Console.WriteLine("Framework not supported: " + framework);
					return 2;
			}

			var parameters = new WriterParameters();

			if (keyPath != null)
			{
				// load signing key
				var rsa = new RSACryptoServiceProvider();
				rsa.ImportCspBlob(File.ReadAllBytes(keyPath));
				parameters.StrongNameKeyPair = new StrongNameKeyPair(rsa.ExportCspBlob(true));
			}

			var asm = AssemblyDefinition.ReadAssembly(input);

			asm.MainModule.Attributes = ModuleAttributes.ILOnly;
			
			
			for (int i = 0; i < asm.CustomAttributes.Count; i++)
			{
				var a = asm.CustomAttributes[i];
				//Console.WriteLine(a.AttributeType.FullName);
				switch (a.AttributeType.FullName)
				{
					case "System.CLSCompliantAttribute":
						if (remap)
						{
							asm.CustomAttributes.RemoveAt(i);
							i--;
						}
						continue;
					case "System.Runtime.Versioning.TargetFrameworkAttribute":
						if (framework == null)
						{
							// remove the attribute for .NET Framework
							asm.CustomAttributes.RemoveAt(i);
							i--;
							continue;
						}
						a.ConstructorArguments.Add(new CustomAttributeArgument(a.ConstructorArguments[0].Type, framework));
						a.ConstructorArguments.RemoveAt(0);
						a.Properties.Clear();
						if (frameworkName != null)
						{
							a.Properties.Add(new Mono.Cecil.CustomAttributeNamedArgument("FrameworkDisplayName", new CustomAttributeArgument(a.ConstructorArguments[0].Type, frameworkName)));
						}
						break;
				}
			}

			if (framework == null)
			{
				asm.SecurityDeclarations.Clear();
				asm.MainModule.Runtime = TargetRuntime.Net_2_0;
			}

			var asnCore = AssemblyNameReference.Parse("mscorlib, Version=" + corlibVersion + ", Culture=neutral, PublicKeyToken=" + corlibToken);
			var asnCptCsp = AssemblyNameReference.Parse("System.Security.Cryptography.Csp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
			var asnCptAlgorithms = AssemblyNameReference.Parse("System.Security.Cryptography.Algorithms, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
			var asnCptPrimitives = AssemblyNameReference.Parse("System.Security.Cryptography.Primitives, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
			var asnRuntime = AssemblyNameReference.Parse("System.Runtime, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");

			asm.MainModule.AssemblyReferences.Clear();
			asm.MainModule.AssemblyReferences.Add(asnCore);

			if (remap)
			{
				foreach (var r in asm.MainModule.GetTypeReferences())
				{
					if (r.FullName.StartsWith("System.Security.Cryptography.Random"))
						r.Scope = asnCptAlgorithms;
					else if (r.FullName.StartsWith("System.Security.Cryptography.SHA"))
						r.Scope = asnCptAlgorithms;
					else if (r.FullName.StartsWith("System.Security.Cryptography.IncrementalHash"))
						r.Scope = asnCptAlgorithms;
					else if (r.FullName.StartsWith("System.Security.Cryptography.HashAlgorithmName"))
						r.Scope = asnCptPrimitives;
					else if (r.FullName.StartsWith("System.Security.Cryptography"))
						r.Scope = asnCptCsp;
					else
						r.Scope = asnRuntime;
				}

				//asm.MainModule.AssemblyReferences.Add(csp);
				asm.MainModule.AssemblyReferences.Add(asnCptAlgorithms);
				asm.MainModule.AssemblyReferences.Add(asnCptPrimitives);
				asm.MainModule.AssemblyReferences.Add(asnRuntime);
			}

			asm.Write(output, parameters);

			return 0;
		}
	}
}