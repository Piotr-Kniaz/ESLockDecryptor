DOTNET_VER = 10.0

.PHONY: linux-x64 linux-arm64 clean

linux-x64:
	@echo "Building for linux-x64..."
	@docker build . -f Dockerfile \
		--pull \
		--platform linux/amd64 \
		--target export \
		--build-arg RID=linux-x64 \
		--output type=local,dest=bin/Release/net$(DOTNET_VER)/linux-x64

linux-arm64:
	@echo "Building for linux-arm64..."
	@docker build . -f Dockerfile \
		--pull \
		--platform linux/arm64 \
		--target export \
		--build-arg RID=linux-arm64 \
		--output type=local,dest=bin/Release/net$(DOTNET_VER)/linux-arm64

# Clear all Docker Images and Build Cache
clean:
	@docker system prune