#if NETCF_1_0
using System;
[assembly: CLSCompliant(true)]
#endif

#if ANDROID || IOS || PORTABLE
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("Rebex.Castle")]
[assembly: AssemblyProduct("Rebex.Castle")]
[assembly: AssemblyCopyright("Copyright © Rebex.NET 2017")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

[assembly: ComVisible(false)]
#endif

#if IOS
// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("3ffd0cf2-a4b5-45ea-b381-46fa5b09a77b")]
#endif