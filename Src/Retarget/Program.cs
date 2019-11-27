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
		public static int Main(string[] args)
		{
			if (args.Length < 3 || args.Length > 4)
			{
				Console.WriteLine("Utility for processing some Rebex assemblies");
				Console.WriteLine("Warning: This is not a general purpose utility. It is only intended to be used with assemblies from https://github.com/rebexnet/elliptic");
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

            string corlibVersion = "4.0.0.0";
			string corlibToken = "b77a5c561934e089";

            bool retarget = false;

			switch (framework)
			{
                case "current":
                    break;
				case "net40":
                    retarget = true;
                    framework = ".NETFramework,Version=v4.0";
					frameworkName = ".NET Framework 4";
					break;
				case "xamarin":
                    retarget = true;
                    framework = null;
					corlibVersion = "2.0.5.0";
					corlibToken = "7cec85d7bea7798e";
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

            if (retarget)
            {
                for (int i = 0; i < asm.CustomAttributes.Count; i++)
                {
                    var a = asm.CustomAttributes[i];
                    //Console.WriteLine(a.AttributeType.FullName);
                    switch (a.AttributeType.FullName)
                    {
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

                asm.MainModule.AssemblyReferences.Clear();
                asm.MainModule.AssemblyReferences.Add(asnCore);
            }

            foreach (var type in asm.MainModule.Types)
            {
                if (!type.IsPublic) continue;
                if (type.FullName.StartsWith("Rebex.", StringComparison.Ordinal)) continue;

                type.IsPublic = false;
            }

			asm.Write(output, parameters);

			return 0;
		}
	}
}