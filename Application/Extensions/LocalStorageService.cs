using System.Text.Json;
using System.Text.Json.Serialization;
using Application.DTOs.Request.Account;
using NetcodeHub.Packages.Extensions.LocalStorage;

namespace Application.Extentions;

public class LocalStorageService(ILocalStorageService localStorageService)
{
    private async Task<string> GetBrowseLocalStorage()
    {
        var tokenModel = await localStorageService.GetEncryptedItemAsStringAsync(Constant.BrowserStorageKey);
        return tokenModel!;
    }

    public async Task<LocalStorageDto> GetModelFromToken()
    {
        try
        {
            string token = await GetBrowseLocalStorage();
            if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
                return new LocalStorageDto();
            return DeserializeJsonString<LocalStorageDto>(token);
        }
        catch
        {
            return new LocalStorageDto();

        }
    }

    public async Task SetBrowserLocalStorage(LocalStorageDto localStorageDTO)
    {
        try
        {
            string token = SerializeObj(localStorageDTO);
            await localStorageService.SaveAsEncryptedStringAsync(Constant.BrowserStorageKey, token);
        }
        catch
        {
        }
    }

    public async Task RemoveTokenFromBrowserLocalStorage()
        => await localStorageService.DeleteItemAsync(Constant.BrowserStorageKey);

    private static string SerializeObj<T>(T modelObject)
        => JsonSerializer.Serialize(modelObject, JsonOptions());

    private static T DeserializeJsonString<T>(string jsonString)
        => JsonSerializer.Deserialize<T>(jsonString, JsonOptions())!;

    private static JsonSerializerOptions JsonOptions()
    {
        return new JsonSerializerOptions
        {
            AllowTrailingCommas = true,
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip

        };
    }
} 


