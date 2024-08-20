using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Verkle.Bindings;

internal static unsafe partial class NativeMethods
{
    
    private static string? _libraryFallbackPath;
    
    static NativeMethods()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += OnResolvingUnmanagedDll;
    }
    
    private static nint OnResolvingUnmanagedDll(Assembly context, string name)
    {
        if (_libraryFallbackPath is null)
        {
            string platform;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                name = $"lib{name}.so";
                platform = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                name = $"lib{name}.dylib";
                platform = "osx";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                name = $"{name}.dll";
                platform = "win";
            }
            else
                throw new PlatformNotSupportedException();

            string arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

            _libraryFallbackPath = Path.Combine("runtimes", $"{platform}-{arch}", "native", name);
        }

        return NativeLibrary.Load(_libraryFallbackPath, context, default);
    }
    
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe partial struct Context
    {
    }
}