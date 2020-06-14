using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace BasicAuhtenticationHandlers.Handlers
{
    public class BasicAuthHandler : DelegatingHandler
    {

        /// <summary>
        /// Set to the Authorization header Scheme value that this filter is intended to support
        /// </summary>
        public const string SupportedTokenScheme = "Basic";


        protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
        {

            // STEP 1: extrai as credencias que estão no header.authorization que está na requisição do pedido
            var authHeader = request.Headers.Authorization;


            //STEP 2: Se não tiver dados no request.Headers.Authorization (Não for passado pea origem)
            //Então pode retornar 401 (Unauthorized) 
            if (authHeader == null)
            {

                //Create the response Message
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Tipo de autenticação invalida (Authentication Type: Basic)")
                };
                // Note: TaskCompletionSource creates a task that does not contain a delegate.
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);

                return await tsc.Task;

            }

            // STEP 3: Se o token scheme enviado pelo cliente não for entendido pelo autenticador
            //Então aborda este pedido retornar 401 (Unauthorized) 
            var tokenType = authHeader.Scheme;
            if (!tokenType.Equals(SupportedTokenScheme))
            {

                //Create the response Message
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Tipo de autenticação invalida (Authentication Type: Basic)")
                };

                // response.Content = Newtonsoft.Json.JsonWriter()
                // Note: TaskCompletionSource creates a task that does not contain a delegate.
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);

                return await tsc.Task;
            }

            // STEP 4: Verifica os parametros passados no schema do Basic Authencication
            var credentials = authHeader.Parameter;
            if (String.IsNullOrEmpty(credentials))
            {
                //Create the response Message
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Não ha dados presente no schema do (Authentication Type: Basic)")
                };

                // response.Content = Newtonsoft.Json.JsonWriter()
                // Note: TaskCompletionSource creates a task that does not contain a delegate.
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);

                return await tsc.Task;
            }

            // STEP 5: Valida as crendecias enviadas se estiver correcto cria o Iprincipal
            // se não retona ERRO
            IPrincipal principal = await ValidateCredentialsAsync(credentials, cancellationToken);
            if (principal == null)
            {
                //Create the response Message
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Credenciais invalida (Authentication Type: Basic)")
                };

                // response.Content = Newtonsoft.Json.JsonWriter()
                // Note: TaskCompletionSource creates a task that does not contain a delegate.
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);

                return await tsc.Task;
            }
            else
            {
                // We have a valid, authenticated user; save off the IPrincipal instance
                //  context.Principal = principal;
                return await base.SendAsync(request, cancellationToken);
            }

            // return await base.SendAsync(request, cancellationToken);

        }



        /// <summary>
        /// Internal method to validate the credentials included in the request,
        /// returning an IPrincipal for the resulting authenticated entity.
        /// </summary>
        private async Task<IPrincipal> ValidateCredentialsAsync(string credentials, CancellationToken cancellationToken)
        {
            // TODO: your credential validation logic here, hopefully async!!
            // crack open the basic auth credentials
            var subject = ParseBasicAuthCredential(credentials);

            // in your system you would probably do an async database lookup...
            if (String.IsNullOrEmpty(subject.Item2) || subject.Item2 != "abc123")
                return null;

            // TODO: Create an IPrincipal (generic or custom), holding an IIdentity (generic or custom)
            //Note a very useful IPrincipal/IIdentity is ClaimsPrincipal/ClaimsIdentity if 
            //you need both subject identifier (ex. user name), plus a set of attributes (claims) 
            //about the subject. 
            IList<Claim> claimCollection = new List<Claim>
            {
                new Claim(ClaimTypes.Name, subject.Item1),
                // you can add other standard or custom claims here based on your username/password lookup...
                new Claim(ClaimTypes.AuthenticationInstant, DateTime.UtcNow.ToString("o")),
                new Claim("urn:MyCustomClaim", "my special value")
                // etc.
            };
            // we'll include the specific token scheme as "authentication type" that was successful 
            // in authenticating the user so downstream code can verify it was a token type 
            // sufficient for the activity the code is attempting.
            var identity = new ClaimsIdentity(claimCollection, SupportedTokenScheme);
            var principal = new ClaimsPrincipal(identity);

            return await Task.FromResult(principal);
        }

        /// <summary>
        /// Converte o a string do Basic Auth em username e password
        /// </summary>
        /// <returns>Tuple<string, string> where first item is subject, second item is password</returns>
        private Tuple<string, string> ParseBasicAuthCredential(string credential)
        {
            string password = null;
            var subject = (Encoding.GetEncoding("iso-8859-1").GetString(Convert.FromBase64String(credential)));
            if (String.IsNullOrEmpty(subject))
                return new Tuple<string, string>(null, null);

            if (subject.Contains(":"))
            {
                var index = subject.IndexOf(':');
                password = subject.Substring(index + 1);
                subject = subject.Substring(0, index);
            }

            return new Tuple<string, string>(subject, password);
        }

    }
}