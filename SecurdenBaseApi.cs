using System.Net;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text;
using System.Net.Http.Json;
using System.Text.Json;
using System.Collections.Generic;

namespace SecurdenApiProtocol
{

    public interface ISecurdenApiClient : IDisposable
    {
        T? GetAsync<T>(string endpoint, IEnumerable<KeyValuePair<string, string>>? a);
        T? PostFormdata<T>(string endpoint, IEnumerable<KeyValuePair<string, string>> formData);
    }

    public class BaseApiClient : ISecurdenApiClient
    {
        private HttpClient _httpClient;
        private string _authToken = "";
        private bool _disposed = false;
        public BaseApiClient(string baseUrl, string authToken)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new ArgumentNullException(nameof(baseUrl));

            if (string.IsNullOrWhiteSpace(authToken))
                throw new ArgumentNullException(nameof(authToken));

            _authToken = authToken;
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };

            _httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(baseUrl),
            };
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Add("authtoken", _authToken);
        }
        public T? GetAsync<T>(string endpoint, IEnumerable<KeyValuePair<string, string>>? queryParams)
        {


            if (queryParams != null && queryParams.Any())
            {
                var query = string.Join("&", queryParams.Select(kvp => $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}"));
                endpoint += endpoint.Contains('?') ? "&" + query : "?" + query;
            }

            var response = _httpClient.GetAsync(endpoint).GetAwaiter().GetResult();
            //response.EnsureSuccessStatusCode();

            var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return JsonSerializer.Deserialize<T>(json);
        }
        public T? PostFormdata<T>(string endpoint, IEnumerable<KeyValuePair<string, string>> formData)
        {
            var content = new FormUrlEncodedContent(formData);
            var response = _httpClient
            .PostAsync(endpoint, content)
            .GetAwaiter()
            .GetResult();
            //response.EnsureSuccessStatusCode();

            var json = response.Content
             .ReadAsStringAsync()
             .GetAwaiter()
             .GetResult();

            return JsonSerializer.Deserialize<T>(json);
        }
        public void Dispose()
        {
            _disposed = true;
            ((IDisposable)_httpClient).Dispose();
        }
    }
}