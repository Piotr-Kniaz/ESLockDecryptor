FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

ARG RID

RUN apt-get update && apt-get install -y clang zlib1g-dev

COPY . .

RUN dotnet publish -r $RID -o /app/publish

FROM scratch AS export

COPY --from=build /app/publish/ .