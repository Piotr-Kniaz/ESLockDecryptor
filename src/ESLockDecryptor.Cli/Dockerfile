FROM mcr.microsoft.com/dotnet/sdk:10.0-aot AS build

WORKDIR /src

ARG RID

COPY . .

RUN dotnet publish -r $RID -o /app/publish

FROM scratch AS export

COPY --from=build /app/publish/ .