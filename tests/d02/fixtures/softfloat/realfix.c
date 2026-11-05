/* Real-object fixture for toolchain/tests/test_check_softfloat_symbols.py: compiled for big-endian soft-float
 * MIPS32r2 o32 (the target's ABI), one function per section, nothing inlined. NOT franken-dsp code; the function
 * names say what each is for. Built with:
 *   zig cc -target mips-linux-musleabi -O2 -g0 -ffunction-sections -fno-asynchronous-unwind-tables -c realfix.c
 * Expected f64 soft-float helper references, read independently with llvm-readelf -r:
 *   section_like   : __extendsfdf2 __muldf3 __adddf3 __truncdfsf2   (the shape of Section::process)
 *   old_conversion : __extendsfdf2 __muldf3 __gedf2 __fixdfsi       (the shape of the retired f64 conversion)
 *   int_conversion : none                                           (integer arithmetic only)
 *   root           : calls section_like and int_conversion (and a static helper that calls old_conversion's twin)
 * __gtsf2 style (f32) helpers are not f64 and must not be reported.
 */
#define NOINLINE __attribute__((noinline))

NOINLINE float section_like(float x, double *z1, double *z2)
{
    double xd = x;
    double y = 0.5 * xd + *z1;
    *z1 = 0.25 * xd + 0.125 * y + *z2;
    *z2 = 0.0625 * xd + 0.03125 * y;
    return (float)y;
}

NOINLINE int old_conversion(float x)
{
    double d = x * 32768.0;
    if (d >= 32767.0)
        return 32767;
    return (int)d;
}

NOINLINE int int_conversion(int bits)
{
    int exp = (bits >> 23) & 0xff;
    int man = (bits & 0x7fffff) | 0x800000;
    return exp > 134 ? 32767 : (man >> (150 - exp)) & 0x7fff;
}

/* A file-local function: calls to it resolve through a local symbol or a section symbol, not a global name. */
NOINLINE static int local_helper(float x)
{
    return old_conversion(x) + 1;
}

NOINLINE int root(float x, int bits, double *z1, double *z2)
{
    float y = section_like(x, z1, z2);
    return int_conversion(bits) + local_helper(y) + (int)(y > 0.0f);
}
