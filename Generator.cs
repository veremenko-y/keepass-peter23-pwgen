/*
    Yaroslav Veremenko <yaroslav@veremenko.inf> (c) 2017
    Based on code of:
    Peter <i@peter23.com> 2011  http://genpas.peter23.com/
    KATO Kazuyoshi <kzys@8-p.info>  http://8-p.info/pwgen/
    Frank4DD  http://www.frank4dd.com/howto/various/pwgen.htm
 
    This program is a C# port of pwgen.
    The original C source code written by Theodore Ts'o.
    <http://sourceforge.net/projects/pwgen/>
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Security;

namespace YvPwGenPeter23
{
    public sealed class Generator : CustomPwGenerator
    {
        private const string specialCharacters = @"!""#$%&'()*+,-./:;<=>?@[\]^_`{|}~";

        private static readonly PwUuid uuid = new PwUuid(new byte[]
	    {
	        0x3b, 0x9a, 0xac, 0x37, 0xa2, 0xb, 0x4e, 0x46, 0x82, 0x45, 0x58, 0x6e, 0xed, 0x5a, 0x63, 0x76
	    });

        private static readonly Dictionary<string, PwGenType> elements = new Dictionary<string, PwGenType>
        {
            {"a", PwGenType.Vowel},
            {"ae", PwGenType.Vowel | PwGenType.Dipthong},
            {"ah", PwGenType.Vowel | PwGenType.Dipthong},
            {"ai", PwGenType.Vowel | PwGenType.Dipthong},
            {"b", PwGenType.Consonant},
            {"c", PwGenType.Consonant},
            {"ch", PwGenType.Consonant | PwGenType.Dipthong},
            {"d", PwGenType.Consonant},
            {"e", PwGenType.Vowel},
            {"ee", PwGenType.Vowel | PwGenType.Dipthong},
            {"ei", PwGenType.Vowel | PwGenType.Dipthong},
            {"f", PwGenType.Consonant},
            {"g", PwGenType.Consonant},
            {"gh", PwGenType.Consonant | PwGenType.Dipthong | PwGenType.NotFirst},
            {"h", PwGenType.Consonant},
            {"i", PwGenType.Vowel},
            {"ie", PwGenType.Vowel | PwGenType.Dipthong},
            {"j", PwGenType.Consonant},
            {"k", PwGenType.Consonant},
            {"l", PwGenType.Consonant},
            {"m", PwGenType.Consonant},
            {"n", PwGenType.Consonant},
            {"ng", PwGenType.Consonant | PwGenType.Dipthong | PwGenType.NotFirst},
            {"o", PwGenType.Vowel},
            {"oh", PwGenType.Vowel | PwGenType.Dipthong},
            {"oo", PwGenType.Vowel | PwGenType.Dipthong},
            {"p", PwGenType.Consonant},
            {"ph", PwGenType.Consonant | PwGenType.Dipthong},
            {"qu", PwGenType.Consonant | PwGenType.Dipthong},
            {"r", PwGenType.Consonant},
            {"s", PwGenType.Consonant},
            {"sh", PwGenType.Consonant | PwGenType.Dipthong},
            {"t", PwGenType.Consonant},
            {"th", PwGenType.Consonant | PwGenType.Dipthong},
            {"u", PwGenType.Vowel},
            {"v", PwGenType.Consonant},
            {"w", PwGenType.Consonant},
            {"x", PwGenType.Consonant},
            {"y", PwGenType.Consonant},
            {"z", PwGenType.Consonant}
        };

        public override PwUuid Uuid { get { return uuid; } }

        public override string Name { get { return "PwGenPeter23"; } }

        public override ProtectedString Generate(PwProfile pwProfile, CryptoRandomStream cryptoRandomSource)
        {   
            Debug.Assert(pwProfile != null);
            Debug.Assert(pwProfile.CustomAlgorithmUuid == Convert.ToBase64String(uuid.UuidBytes, Base64FormattingOptions.None));

            ProtectedString result;
            while (true)
            {
                result = GeneratePassword(pwProfile, cryptoRandomSource);
                if (result != null) break;
            }

            return new ProtectedString(false, result.ReadString());
        }

        private ProtectedString GeneratePassword(PwProfile pwProfile, CryptoRandomStream cryptoRandomSource)
        {
            var result = "";
            PwGenType previous = 0;
            var isFirst = true;
            var shouldBe = GetRandomDouble(cryptoRandomSource) < 0.5 ? PwGenType.Vowel : PwGenType.Consonant;
            var includeNumber = true;
            var includeCapital = true;
            var includeSpecial = true;
            while (result.Length< pwProfile.Length)
            {
                var i = (int)Math.Floor((elements.Count - 1) * GetRandomDouble(cryptoRandomSource));
                var el = elements.ElementAt(i);
                var subset = el.Key;
                var flags = el.Value;

                /* Filter on the basic type of the next element */
                if ((flags & shouldBe) == 0)
                {
                    continue;
                }
                /* Handle the .NotFirst flag */
                if (isFirst && flags.HasFlag(PwGenType.NotFirst))
                {
                    continue;
                }
                /* Don't allow .Vowel followed a .Vowel/.Dipthong pair */
                if (previous.HasFlag( PwGenType.Vowel) && flags.HasFlag(PwGenType.Vowel) && flags.HasFlag(PwGenType.Dipthong))
                {
                    continue;
                }

                /* Don't allow us to overflow the buffer */
                if (result.Length + subset.Length > pwProfile.Length)
                {
                    continue;
                }

                if (includeCapital)
                {
                    if ((isFirst || flags.HasFlag(PwGenType.Consonant)) &&
                        (GetRandomDouble(cryptoRandomSource) > 0.3))
                    {
                        subset = subset.Substring(0, 1).ToUpper() + subset.Substring(1, subset.Length - 1);
                        includeCapital = false;
                    }
                }

                /*
                 * OK, we found an element which matches our criteria,
                 * let's do it!
                 */
                result += subset;

                if (includeNumber)
                {
                    if (!isFirst && GetRandomDouble(cryptoRandomSource) < 0.3)
                    {
                        if (result.Length+ subset.Length > pwProfile.Length)
                        {
                            result = result.Remove(result.Length - 1);
                        }
                        result += ((int) Math.Floor(10*GetRandomDouble(cryptoRandomSource))).ToString();
                        includeNumber = false;
                        isFirst = true;
                        previous = 0;
                        shouldBe = GetRandomDouble(cryptoRandomSource) < 0.5 ? PwGenType.Vowel : PwGenType.Consonant;
                        continue;
                    }
                }

                if (includeSpecial)
                {
                    if (!isFirst && (GetRandomDouble(cryptoRandomSource) < 0.3))
                    {
                        if (result.Length + subset.Length > pwProfile.Length)
                        {
                            result = result.Remove(result.Length - 1);
                        }

                        var specialChar = specialCharacters[(int)Math.Floor(GetRandomDouble(cryptoRandomSource) * specialCharacters.Length)];
                        result += specialChar;
                        includeSpecial = false;

                        isFirst = true;
                        previous = 0;
                        shouldBe = GetRandomDouble(cryptoRandomSource) < 0.5 ? PwGenType.Vowel : PwGenType.Consonant;
                        continue;
                    }
                }

                /*
                 * OK, figure out what the next element should be
                 */
                if (shouldBe == PwGenType.Consonant)
                {
                    shouldBe = PwGenType.Vowel;
                }
                else
                { 
                    /* should_be == .Vowel */
                    if (previous.HasFlag(PwGenType.Vowel) ||
                        flags.HasFlag(PwGenType.Dipthong) || 
                        (GetRandomDouble(cryptoRandomSource) > 0.3))
                    {
                        shouldBe = PwGenType.Consonant;
                    }
                    else
                    {
                        shouldBe = PwGenType.Vowel;
                    }
                }
                previous = flags;
                isFirst = false;
            }

            if (includeCapital || includeNumber || includeSpecial)
            {
                return null;
            }

            return new ProtectedString(true, result);
        }

        private static double GetRandomDouble(CryptoRandomStream cryptoRandomSource)
        {
            return cryptoRandomSource.GetRandomUInt64() / (double)ulong.MaxValue;
        }
    }
}
