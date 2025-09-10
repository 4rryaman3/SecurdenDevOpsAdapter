using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecurdenApiProtocol
{
    public interface ISecurdenApiClient : IDisposable
    {
        T? GetAsync<T>(string endpoint, IEnumerable<KeyValuePair<string, string>>? a);
        T? PostFormdata<T>(string endpoint, IEnumerable<KeyValuePair<string, string>> formData);
    }

    public class BaseApiClient : ISecurdenApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly HttpClientHandler _handler;
        private readonly string _authToken = "";
        private bool _disposed;

        public BaseApiClient(string baseUrl, string authToken,
            string? clientCertificatePath = null,
            string? clientCertificatePassword = null,
            bool allowSelfSignedServerCertificate = false,
            bool preferStrongestTls = true)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new ArgumentNullException(nameof(baseUrl));
            if (string.IsNullOrWhiteSpace(authToken))
                throw new ArgumentNullException(nameof(authToken));

            _authToken = authToken;

    #if NET6_0_OR_GREATER
            _handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate, SslProtocols = SslProtocols.None
            };

            if (allowSelfSignedServerCertificate)
            {
                // Scoped to this handler only (safe for dev/test)
                _handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
        #else
            // .NET Framework 4.8: TLS 1.3 is not supported; use system defaults (TLS 1.2+ as configured by OS)
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.SystemDefault;
            }
            catch
            {
                ServicePointManager.SecurityProtocol =
                    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            }

            _handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };

            if (allowSelfSignedServerCertificate)
            {
                // Affects the whole AppDomain on .NET Framework (dev only!)
                ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) => true;
            }
        #endif

            if (!string.IsNullOrWhiteSpace(clientCertificatePath) && File.Exists(clientCertificatePath))
            {
                try
                {
                    var flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
                    var clientCert = string.IsNullOrEmpty(clientCertificatePassword)
                        ? new X509Certificate2(clientCertificatePath, (string?)null, flags)
                        : new X509Certificate2(clientCertificatePath, clientCertificatePassword, flags);

                    _handler.ClientCertificates.Add(clientCert);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        $"Failed to load client certificate from '{clientCertificatePath}'. " +
                        $"Verify path/password and that the file is a PFX/P12. Inner: {ex.Message}", ex);
                }
            }

            _httpClient = new HttpClient(_handler)
            {
                BaseAddress = new Uri(baseUrl, UriKind.Absolute),
                Timeout = TimeSpan.FromSeconds(100)
            };
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Add("authtoken", _authToken);
        }

        public T? GetAsync<T>(string endpoint, IEnumerable<KeyValuePair<string, string>>? queryParams)
        {
            try
            {
                if (queryParams != null && queryParams.Any())
                {
                    var query = string.Join("&", queryParams.Select(kvp =>
                        $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}"));
                    endpoint += endpoint.Contains('?') ? "&" + query : "?" + query;
                }

                using (var response = _httpClient.GetAsync(endpoint).GetAwaiter().GetResult())
                {
                    return HandleResponse<T>(endpoint, response);
                }
            }
            catch (Exception ex)
            {
                throw WrapTlsHttpException(ex, endpoint);
            }
        }

        public T? PostFormdata<T>(string endpoint, IEnumerable<KeyValuePair<string, string>> formData)
        {
            try
            {
                using (var content = new FormUrlEncodedContent(formData))
                using (var response = _httpClient.PostAsync(endpoint, content).GetAwaiter().GetResult())
                {
                    return HandleResponse<T>(endpoint, response);
                }
            }
            catch (Exception ex)
            {
                throw WrapTlsHttpException(ex, endpoint);
            }
        }

        private static T? HandleResponse<T>(string endpoint, HttpResponseMessage response)
        {
            var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                var msg = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase} for {endpoint}. Body: {Truncate(json, 1024)}";
                throw new HttpRequestException(msg);
            }

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return string.IsNullOrWhiteSpace(json) ? default : JsonSerializer.Deserialize<T>(json, options);
        }

        private static string Truncate(string? s, int max)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Length <= max ? s : s.Substring(0, max) + "...(truncated)";
        }
        private static HttpStatusCode? TryGetStatusCode(Exception ex)
        {
        #if NET5_0_OR_GREATER
            if (ex is HttpRequestException hre && hre.StatusCode.HasValue)
                return hre.StatusCode.Value;
        #endif
            var m = Regex.Match(ex.Message ?? string.Empty, @"HTTP\s+(\d{3})\b");
            if (m.Success && int.TryParse(m.Groups[1].Value, out var codeInt)
                && Enum.IsDefined(typeof(HttpStatusCode), codeInt))
            {
                return (HttpStatusCode)codeInt;
            }
            return null;
        }

        private Exception WrapTlsHttpException(Exception ex, string endpoint)
        {
            var status = TryGetStatusCode(ex);
            if (status == HttpStatusCode.OK || status == HttpStatusCode.Forbidden)
                return ex;

            if (ex is HttpRequestException || ex is AuthenticationException || ex.InnerException is AuthenticationException)
            {
                var detail =
                    "Likely TLS/SSL handshake issue. " +
                    "Check:\n" +
                    " - Server certificate trust chain and hostname (CN/SAN)\n" +
                    " - Mutual TLS requirements (did the server require a client certificate?)\n" +
                    " - TLS protocol/cipher support (server should allow TLS 1.2+; TLS 1.3 requires .NET 6/7/8 + OS support)\n";

                return new HttpRequestException(
                    $"Request to '{endpoint}' failed: {ex.Message}\n{detail}", ex);
            }

            return new HttpRequestException($"Request to '{endpoint}' failed: {ex.Message}", ex);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _httpClient?.Dispose();
            _handler?.Dispose();
        }
    }
}
