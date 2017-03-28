using System;

namespace YvPwGenPeter23
{
    [Flags]
    internal enum PwGenType
    {
        Consonant = 1,
        Vowel = 1 << 1,
        Dipthong = 1 << 2,
        NotFirst = 1 << 3
    }
}