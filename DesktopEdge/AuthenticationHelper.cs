using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ziti.Desktop.Edge
{
    internal class AuthenticationHelper
    {
        public async Task<string> AcquireAccessTokenAsync(string clientId, string authority, string[] scopes)
        {
            var clientApplication = PublicClientApplicationBuilder.Create(clientId)
                .WithAuthority(authority)
                .WithRedirectUri("http://localhost")
                .Build();

            var result = await clientApplication.AcquireTokenInteractive(scopes).ExecuteAsync();

            if (result != null && result.AccessToken != null)
            {
                return result.AccessToken;
            }
            else
            {
                throw new Exception("Failed to acquire token");
            }
        }
    }
}
