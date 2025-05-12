using System;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text;
using System.ComponentModel;
using System.Globalization;

namespace SecurdenApiProtocol
{
    public class AccountDto
    {
        [JsonPropertyName("account_id")]
        public long? AccountId { get; set; }

        [JsonPropertyName("account_name")]
        public string? AccountName { get; set; }

        [JsonPropertyName("account_title")]
        public string? AccountTitle { get; set; }

        [JsonPropertyName("password")]
        public string? Password { get; set; }

        [JsonPropertyName("address")]
        public string? Address { get; set; }

        [JsonPropertyName("port")]
        public string? Port { get; set; }

        [JsonPropertyName("status_code")]
        public int? StatusCode { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? additionalData { get; set; }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("{");

            if (AccountId != null) sb.Append($"\"account_id\": {AccountId},");
            if (!string.IsNullOrEmpty(AccountName)) sb.Append($"\"account_name\": \"{AccountName}\",");
            if (!string.IsNullOrEmpty(AccountTitle)) sb.Append($"\"account_title\": \"{AccountTitle}\",");
            if (sb[sb.Length - 1] == ',')
                sb.Length--;
            sb.Append("}");
            return sb.ToString();
        }

    }
    public class ApiResponse
    {
        [JsonPropertyName("status_code")]
        public int? StatusCode { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? AdditionalResponse { get; set; }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("{");

            if (StatusCode != null) sb.Append($"\"StatusCode\": {StatusCode},");
            if (!string.IsNullOrEmpty(Message)) sb.Append($"\"Message\": \"{Message}\",");
            if (sb[sb.Length - 1] == ',')
                sb.Length--;
            sb.Append("}");
            return sb.ToString();
        }
    }
    public class accountPassword
    {
        [JsonPropertyName("password")]
        public string? Password { get; set; }

        [JsonPropertyName("label")]
        public string? Label { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? additionalData { get; set; }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("{");
            if (!string.IsNullOrEmpty(Label)) sb.Append($"\"password_label\": \"{Label}\",");
            if (sb[sb.Length - 1] == ',')
                sb.Length--;
            sb.Append("}");
            return sb.ToString();
        }
    }
    public class SecurdenApiAdapter : IDisposable
    {

        private readonly BaseApiClient _baseClient;
        public readonly List<string> fields = ["account_id", "account_name", "account_title", "account_type", "account_category", "domain_account_name", "ticket_id", "reason", "new_password", "is_remote"];
        public SecurdenApiAdapter(string baseUrl, string authToken)
        {
            _baseClient = new BaseApiClient(baseUrl, authToken);
        }
        public AccountDto? GetSpecificAccount(List<KeyValuePair<string, string>>? accountParams = null)
        {
            var filteredParams = new List<KeyValuePair<string, string>>();

            if (accountParams != null)
            {
                filteredParams = accountParams
                    .Where(kvp => fields.Contains(kvp.Key))
                    .ToList();
            }

            var returnObj = _baseClient.GetAsync<AccountDto>("/secretsmanagement/get_account", filteredParams);
            return returnObj;
        }
        public List<AccountDto> GetAccounts(List<string>? accountIdsList = null, List<Dictionary<string, string>>? accountParams = null)
        {
            var returnObj = new List<AccountDto>();

            if (accountIdsList == null || accountIdsList.Count == 0)
                return returnObj;

            var accountIdParams = "[" + string.Join(",", accountIdsList) + "]";

            var filteredParamsList = new List<Dictionary<string, string>>();
            if (accountParams != null)
            {
                filteredParamsList = accountParams
                    .Select(dict => dict
                        .Where(kvp => fields.Contains(kvp.Key))
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value))
                    .ToList();
            }

            var accountsJson = JsonSerializer.Serialize(filteredParamsList);
            var formData = new List<KeyValuePair<string, string>>
                {
                    new("account_ids", accountIdParams),
                    new("accounts", accountsJson)
                };

            var accountResponse = _baseClient.PostFormdata<ApiResponse>("/secretsmanagement/get_accounts", formData);

            if (accountResponse?.AdditionalResponse != null)
            {
                foreach (var kvp in accountResponse.AdditionalResponse)
                {
                    var dto = kvp.Value.Deserialize<AccountDto>();
                    if (dto != null)
                        returnObj.Add(dto);
                }
            }

            return returnObj;
        }
        public accountPassword? GetAccountPassword(List<KeyValuePair<string, string>>? accountParams = null)
        {
            var returnObj = new accountPassword();
            if (accountParams == null)
            {
                return returnObj;
            }
            var filteredParams = accountParams
                .Where(kvp => fields.Contains(kvp.Key))
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            returnObj = _baseClient.GetAsync<accountPassword>("/secretsmanagement/get_password_via_tools", filteredParams);
            return returnObj;
        }
        public ApiResponse? ChangePassword(List<KeyValuePair<string, string>>? accountParams = null) {
            var returnObj = new ApiResponse();
            if (accountParams == null)
            {
                return returnObj;
            }
            var filteredParams = accountParams
                .Where(kvp => fields.Contains(kvp.Key))
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            returnObj = _baseClient.PostFormdata<ApiResponse>("/secretsmanagement/change_remote_password", filteredParams);
            return returnObj;
        }
        public void Dispose()
        {
            _baseClient.Dispose();
        }
    }
}
