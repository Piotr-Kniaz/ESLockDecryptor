FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

RUN apt-get update && apt-get install -y clang zlib1g-dev

COPY . .

RUN dotnet publish -r linux-x64 -o /app/publish

FROM scratch AS export

COPY --from=build /app/publish/ .