FROM mcr.microsoft.com/dotnet/aspnet:6.0-alpine
USER root

WORKDIR /app
EXPOSE 80
COPY . .

ENTRYPOINT dotnet Shaddix.OpenIddict.ExternalAuthentication.Example.dll
