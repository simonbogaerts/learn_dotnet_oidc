using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace ImageGallery.Client.Services
{
    public class ImageGalleryHttpClient : IImageGalleryHttpClient
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private HttpClient _httpClient = new HttpClient();

        public ImageGalleryHttpClient(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        
        public async Task<HttpClient> GetClient()
        {
            // should we renew access and refresh tokens? 
            var expiresAt = await _httpContextAccessor.HttpContext.GetTokenAsync("expires_at");

            string accessToken;
            // compare 
            if (string.IsNullOrWhiteSpace(expiresAt) || ((DateTime.Parse(expiresAt).AddSeconds(-60)).ToUniversalTime() < DateTime.UtcNow))
            {
                //accessToken = await RenewTokens(); disabled because doesnt work in current version
                accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }
            else
            {
                // get accesstoken 
                accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }

            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                _httpClient.SetBearerToken(accessToken);
            }

            _httpClient.BaseAddress = new Uri("https://localhost:44351/");
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            return _httpClient;
        }   
        
        public async Task<string> RenewTokens()
        {
            // current context 
            var currentContext = this._httpContextAccessor.HttpContext;

            // get the metadata 
            var discoveryClient = new DiscoveryClient("https://localhost:44354/");
            var metaDataResponse = await discoveryClient.GetAsync();

            // create a new token client to get new tokens
            var tokenClient = new TokenClient(metaDataResponse.TokenEndpoint, "imagegalleryclient", "secret");

            // get saved refresh token
            var currentRefreshToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

            // refresh the tokens 
            var tokenResult = await tokenClient.RequestRefreshTokenAsync(currentRefreshToken);

            if (!tokenResult.IsError)
            {
                // update the tokens and expiration values 
                var updatedTokens = new List<AuthenticationToken>();
                updatedTokens.Add(new AuthenticationToken 
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = tokenResult.IdentityToken
                });
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.AccessToken,
                    Value = tokenResult.AccessToken
                });
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.RefreshToken,
                    Value = tokenResult.RefreshToken
                });

                var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(tokenResult.ExpiresIn);
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = "expires_at",
                    Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                });

                // get authentication result , containing current principal & properties
                var currentAuthenticateResult = await currentContext.AuthenticateAsync("Cookies");

                currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

                // sign in 
                await this._httpContextAccessor.HttpContext.SignInAsync(
                    "Cookies",
                    currentAuthenticateResult.Principal,
                    currentAuthenticateResult.Properties);

                // return new accesstoken
                return tokenResult.AccessToken;
            } 
            else
            {
                throw new Exception("Problem encountered while refreshing tokens.", tokenResult.Exception);
            }
        }
    }
}

