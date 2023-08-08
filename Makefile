.DEFAULT_GOAL     := help

GREP               ?= $(shell command -v ggrep 2> /dev/null || command -v grep 2> /dev/null)
AWK                ?= $(shell command -v gawk 2> /dev/null || command -v awk 2> /dev/null)
DOCKER             ?= docker
PROJECT_NAME       ?= njs-acme
DOCKER_IMAGE_NAME  ?= nginx/nginx-$(PROJECT_NAME)
GITHUB_REPOSITORY  ?= nginx/$(PROJECT_NAME)
SRC_REPO           := https://github.com/$(GITHUB_REPOSITORY)

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
	$(DOCKER) buildx build $(DOCKER_BUILD_FLAGS) -t $(DOCKER_IMAGE_NAME) .


.PHONY: docker-copy
docker-copy: CONTAINER_NAME=njs_acme_dist_source
docker-copy: docker-build ## Copy the acme.js file out of the container and save in dist/
	mkdir -p dist
	$(DOCKER) create --name $(CONTAINER_NAME) $(DOCKER_IMAGE_NAME)
	$(DOCKER) cp $(CONTAINER_NAME):/usr/lib/nginx/njs_modules/acme.js dist/acme.js
	$(DOCKER) rm -v $(CONTAINER_NAME)


.PHONY: docker-nginx
docker-nginx: docker-build ## Start nginx container
	$(DOCKER) run --rm -it -p 8000:8000 -p \
		$(DOCKER_IMAGE_NAME)


.PHONY: docker-njs
docker-njs: docker-build ## Start nginx container and run `njs`
	$(DOCKER) run --rm -it \
		$(DOCKER_IMAGE_NAME) njs


.PHONY: docker-devup
docker-devup: docker-build ## Start all docker compose services for development/testing
	$(DOCKER) compose up -d


.PHONY: docker-reload-nginx
docker-reload-nginx: ## Reload nginx started from `docker compose`
	$(DOCKER) compose up -d --force-recreate nginx && $(DOCKER) compose logs -f nginx


.PHONY: docker-integration-tests
docker-integration-tests: docker-copy ## Run integration tests in docker
	$(DOCKER) compose -f ./integration-tests/docker-compose.yml build
	$(DOCKER) compose -f ./integration-tests/docker-compose.yml up -d pebble
	$(DOCKER) compose -f ./integration-tests/docker-compose.yml up --no-log-prefix test
