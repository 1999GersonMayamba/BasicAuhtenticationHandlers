using BasicAuhtenticationHandlers.Handlers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

namespace BasicAuhtenticationHandlers
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Serviços e configuração da API da Web

            // Rotas da API da Web
            config.MapHttpAttributeRoutes();

            //Aqui registamos o nosso manipuador de mensagem personalizado
            config.MessageHandlers.Add(new BasicAuthHandler());

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
