using Blazored.LocalStorage;

namespace ClientLibrary.Helpers
{
    public class LocalStorageService(ILocalStorageService localStorageService)
    {
        private const string TokenKey = "authentication-token";
        private const string ThemeKey = "theme";
        public async Task<string> GetToken() => await localStorageService.GetItemAsStringAsync(TokenKey);
        public async Task SetToken(string token) => await localStorageService.SetItemAsStringAsync(TokenKey, token);
        public async Task RemoveToken() => await localStorageService.RemoveItemAsync(TokenKey);

        public async Task<string> GetThemeAsync() => await localStorageService.GetItemAsStringAsync(ThemeKey);
        public async Task SetThemeAsync(string theme) => await localStorageService.SetItemAsStringAsync(ThemeKey, theme);
    }
}
