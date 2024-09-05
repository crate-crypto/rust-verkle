using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using static Verkle.Bindings.NativeMethods;

namespace Verkle.Bindings;

public unsafe class RustVerkle: IDisposable
{
    private Context* _context = context_new();

    public void Dispose()
    {
        if (_context != null)
        {
            context_free(_context);
            _context = null;
        }
    }

    public void PedersenHash(byte[] address, byte[] treeIndexLe, byte[] outHash)
    {
        fixed (byte* addrPtr = address)
        fixed (byte* indexPtr = treeIndexLe)
        fixed (byte* hashPtr = outHash)
        {
            pedersen_hash(_context, addrPtr, indexPtr, hashPtr);
        }
    }
}