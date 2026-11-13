FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY lab.csproj .
RUN dotnet restore
COPY Program.cs .
RUN dotnet publish -c Release -o /app --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:8.0
COPY --from=build /app /app
WORKDIR /app
CMD ["dotnet", "lab.dll"]
