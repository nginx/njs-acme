.DEFAULT_GOAL     := help

GREP               ?= $(shell command -v ggrep 2> /dev/null || command -v grep 2> /dev/null)
AWK                ?= $(shell command -v gawk 2> /dev/null || command -v awk 2> /dev/null)
DOCKER             ?= docker
PROJECT_NAME       ?= nginx-njs-acme
GITHUB_REPOSITORY  ?= nginxinc/$(PROJECT_NAME)
SRC_REPO           := https://github.com/$(GITHUB_REPOSITORY)
CURRENT_DIR 		= $(shell pwd)

Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: help
help:
	@$(GREP) --no-filename -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		$(AWK) 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}' | sort


.PHONY:
build: ## Run npm run build
	$Q echo "$(M) building in release mode for the current platform"
	$Q npm run build


.PHONY: docker-build
docker-build: ## Build docker image
	$(DOCKER) buildx build $(DOCKER_BUILD_FLAGS) -t $(PROJECT_NAME) .


.PHONY: docker-copy
docker-copy: CONTAINER_ID=$(shell $(DOCKER) create $(PROJECT_NAME))
docker-copy: docker-build ## Copy the acme.js file out of the container and save in dist/
	echo ${CONTAINER_ID}
	mkdir -p dist
	$(DOCKER) cp ${CONTAINER_ID}:/usr/lib/nginx/njs_modules/acme.js dist/acme.js
	$(DOCKER) rm -v ${CONTAINER_ID}


.PHONY: docker-nginx
docker-nginx: docker-build ## Start nginx container
	$(DOCKER) run --rm -it -p 8000:8000 \
		-e "NJS_ACME_DIR=/etc/nginx/njs-acme" \
		$(PROJECT_NAME)


.PHONY: docker-njs
docker-njs: docker-build ## Start nginx container and run `njs`
	$(DOCKER) run --rm -it -p 8000:8000 \
		-e "NJS_ACME_DIR=/etc/nginx/njs-acme" \
		$(PROJECT_NAME) njs


.PHONY: docker-devup
docker-devup: docker-build ## Start all docker compose services
	$(DOCKER) compose up -d


.PHONY: docker-reload-nginx
docker-reload-nginx: ## Reload nginx
	$(DOCKER) compose up -d --force-recreate nginx && $(DOCKER) compose logs -f nginx
