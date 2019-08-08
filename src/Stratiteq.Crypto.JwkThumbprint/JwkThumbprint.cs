using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace Stratiteq.Crypto.JwkThumbprint
{
    public static class JwkThumbprint
    {
        /// <summary>
        /// Computes a thumbprint of the JWK using SHA-256 as per https://tools.ietf.org/html/rfc7638, JSON Web Key (JWK) Thumbprint.
        /// </summary>
        /// <param name="kty">JWA key type.</param>
        /// <param name="crv">Curve type (required for kty=EC).</param>
        /// <param name="x">EC x coordinate (required for kty=EC).</param>
        /// <param name="y">EC y coordinate (required for kty=EC).</param>
        /// <param name="thumbprintEncoding">Decides how the thumbprint should be encoded.</param>
        /// <param name="truncate">Truncates the thumbprint with the given number of bytes (by taking the leftmost bytes from the hash) before applying the encoding.</param>
        public static string ComputeSHA256ThumbprintEC(
            string kty,
            string crv,
            byte[] x,
            byte[] y,
            ThumbprintEncoding thumbprintEncoding,
            byte? truncate = null) =>
            ComputeSHA256Thumbprint(SerializeEC(kty, crv, x, y), thumbprintEncoding, truncate);

        /// <summary>
        /// Computes a thumbprint of the JWK using SHA-256 as per https://tools.ietf.org/html/rfc7638, JSON Web Key (JWK) Thumbprint.
        /// </summary>
        /// <param name="kty">JWA key type.</param>
        /// <param name="e">RSA exponent parameter (required for kty=RSA).</param>
        /// <param name="n">RSA modulus parameter (required for kty=RSA).</param>
        /// <param name="thumbprintEncoding">Decides how the thumbprint should be encoded.</param>
        /// <param name="truncate">Truncates the thumbprint with the given number of bytes (by taking the leftmost bytes from the hash) before applying the encoding.</param>
        public static string ComputeSHA256ThumbprintRSA(
            string kty,
            byte[] e,
            byte[] n,
            ThumbprintEncoding thumbprintEncoding,
            byte? truncate = null) =>
            ComputeSHA256Thumbprint(SerializeRSA(kty, e, n), thumbprintEncoding, truncate);

        /// <summary>
        /// Computes a thumbprint of the JWK using SHA-256 as per https://tools.ietf.org/html/rfc7638, JSON Web Key (JWK) Thumbprint.
        /// </summary>
        /// <param name="kty">JWA key type.</param>
        /// <param name="k">'k' (Symmetric - Key Value).</param>
        /// <param name="thumbprintEncoding">Decides how the thumbprint should be encoded.</param>
        /// <param name="truncate">Truncates the thumbprint with the given number of bytes (by taking the leftmost bytes from the hash) before applying the encoding.</param>
        public static string ComputeSHA256ThumbprintOctet(
            string kty,
            byte[] k,
            ThumbprintEncoding thumbprintEncoding,
            byte? truncate = null) =>
            ComputeSHA256Thumbprint(SerializeOctet(kty, k), thumbprintEncoding, truncate);

        private static string ComputeSHA256Thumbprint(string jwk, ThumbprintEncoding thumbprintEncoding, byte? truncate = null)
        {
            var jwkBytes = Encoding.UTF8.GetBytes(jwk);
            using (var hashAlgorithm = SHA256.Create())
            {
                var hash = hashAlgorithm.ComputeHash(jwkBytes);

                if (truncate.HasValue)
                {
                    hash = hash.Take(truncate.Value).ToArray();
                }

                if (thumbprintEncoding == ThumbprintEncoding.Base64Url)
                {
                    return WebEncoders.Base64UrlEncode(hash);
                }
                else if (thumbprintEncoding == ThumbprintEncoding.Base62)
                {
                    return new Base62Converter().Encode(hash);
                }
                else
                {
                    throw new NotSupportedException($"Thumbprint encoding {thumbprintEncoding} not supported.");
                }
            }
        }

        /// <summary>
        /// Construct a JSON object [RFC7159] containing only the required members of a JWK representing the key and with
        /// no whitespace or line breaks before or after any syntactic elements and with the required members ordered
        /// lexicographically by the Unicode [UNICODE] code points of the member names.
        /// See https://tools.ietf.org/html/rfc7638#section-3.
        /// </summary>
        private static string SerializeEC(string kty, string crv, byte[] x, byte[] y) =>
            SerializeEC(
                crv,
                kty,
                WebEncoders.Base64UrlEncode(x),
                WebEncoders.Base64UrlEncode(y));

        private static string SerializeEC(string kty, string crv, string x, string y) =>
            JsonConvert.SerializeObject(
                new
                {
                    crv,
                    kty,
                    x,
                    y,
                }, Formatting.None);

        /// <summary>
        /// Construct a JSON object [RFC7159] containing only the required members of a JWK representing the key and with
        /// no whitespace or line breaks before or after any syntactic elements and with the required members ordered
        /// lexicographically by the Unicode [UNICODE] code points of the member names.
        /// See https://tools.ietf.org/html/rfc7638#section-3.
        /// </summary>
        private static string SerializeRSA(string kty, byte[] e, byte[] n) =>
            JsonConvert.SerializeObject(
                new
                {
                    e = WebEncoders.Base64UrlEncode(e),
                    kty,
                    n = WebEncoders.Base64UrlEncode(n),
                }, Formatting.None);

        /// <summary>
        /// Construct a JSON object [RFC7159] containing only the required members of a JWK representing the key and with
        /// no whitespace or line breaks before or after any syntactic elements and with the required members ordered
        /// lexicographically by the Unicode [UNICODE] code points of the member names.
        /// See https://tools.ietf.org/html/rfc7638#section-3.
        /// </summary>
        private static string SerializeOctet(string kty, byte[] k) =>
            JsonConvert.SerializeObject(
                new
                {
                    k = WebEncoders.Base64UrlEncode(k),
                    kty,
                }, Formatting.None);
    }
}
