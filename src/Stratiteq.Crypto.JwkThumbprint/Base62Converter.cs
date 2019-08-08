// MIT License

// Copyright(c) 2017 Daniel Destouche

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratiteq.Crypto.JwkThumbprint
{
    public class Base62Converter
    {
#pragma warning disable SA1310 // Field names must not contain underscore
        private const string DEFAULT_CHARACTER_SET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        private const string INVERTED_CHARACTER_SET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
#pragma warning restore SA1310 // Field names must not contain underscore
        private readonly string characterSet;

        public Base62Converter()
        {
            characterSet = DEFAULT_CHARACTER_SET;
        }

        public Base62Converter(CharacterSet charset)
        {
            if (charset == CharacterSet.DEFAULT)
            {
                characterSet = DEFAULT_CHARACTER_SET;
            }
            else
            {
                characterSet = INVERTED_CHARACTER_SET;
            }
        }

        public enum CharacterSet
        {
            /// <summary>
            /// Numbers, upper case, lower case.
            /// </summary>
            DEFAULT,

            /// <summary>
            /// Numbers, lower case, upper case.
            /// </summary>
            INVERTED,
        }

        public string Encode(string value)
        {
            var arr = new int[value.Length];
            for (var i = 0; i < arr.Length; i++)
            {
                arr[i] = value[i];
            }

            return Encode(arr);
        }

        public string Decode(string value)
        {
            var arr = new int[value.Length];
            for (var i = 0; i < arr.Length; i++)
            {
                arr[i] = characterSet.IndexOf(value[i]);
            }

            return Decode(arr);
        }

        public string Encode(byte[] value)
            => Encode(value.Select(x => (int)x).ToArray());

        public string Decode(byte[] value)
            => Decode(value.Select(x => (int)x).ToArray());

        private static int[] BaseConvert(int[] source, int sourceBase, int targetBase)
        {
            var result = new List<int>();
            int count = 0;
            while ((count = source.Length) > 0)
            {
                var quotient = new List<int>();
                int remainder = 0;
                for (var i = 0; i != count; i++)
                {
                    int accumulator = source[i] + (remainder * sourceBase);
                    int digit = accumulator / targetBase;
                    remainder = accumulator % targetBase;
                    if (quotient.Count > 0 || digit > 0)
                    {
                        quotient.Add(digit);
                    }
                }

                result.Insert(0, remainder);
                source = quotient.ToArray();
            }

            return result.ToArray();
        }

        private string Encode(int[] value)
        {
            var converted = BaseConvert(value, 256, 62);
            var builder = new StringBuilder();
            for (var i = 0; i < converted.Length; i++)
            {
                builder.Append(characterSet[converted[i]]);
            }

            return builder.ToString();
        }

        private string Decode(int[] value)
        {
            var converted = BaseConvert(value, 62, 256);
            var builder = new StringBuilder();
            for (var i = 0; i < converted.Length; i++)
            {
                builder.Append((char)converted[i]);
            }

            return builder.ToString();
        }
    }
}
