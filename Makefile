.DEFAULT_GOAL     := help

GREP               ?= $(shell command -v ggrep 2> /dev/null || command -v grep 2> /dev/null)
AWK                ?= $(shell command -v gawk 2> /dev/null || command -v awk 2> /dev/null)
DOCKER             ?= docker
PROJECT_NAME       ?= njs-acme-experemental
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
format: ## Run rustfmt
	$Q echo "$(M) building in release mode for the current platform"


.PHONY:
build: ## Run npm run build
	$Q echo "$(M) building in release mode for the current platform"
	$Q npm run build

.PHONY:
build: ## Run npm run build
	$Q echo "$(M) building in release mode for the current platform"
	$Q npm run build

.PHONY: build-docker
build-docker: ## Build docker image
	$(DOCKER) buildx build $(DOCKER_BUILD_FLAGS) -t $(PROJECT_NAME) .


.PHONY: start-docker
start-docker: build # build-docker ## Start docker container
	$(DOCKER) run --rm -it -p 8000:8000 \
	-e "NJS_ACME_DIR=/etc/nginx/examples" \
	-v $(CURRENT_DIR)/examples:/etc/nginx/examples/ \
	-v $(CURRENT_DIR)/dist:/etc/nginx/dist/ njs-acme-experemental nginx -c examples/nginx.conf


.PHONY: start-docker
start-njs: build # build-docker ## Start docker container
	$(DOCKER) run --rm -it -p 8000:8000 \
	-e "NJS_ACME_DIR=/etc/nginx/examples" \
	-v $(CURRENT_DIR)/examples:/etc/nginx/examples/ \
	-v $(CURRENT_DIR)/dist:/etc/nginx/dist/ njs-acme-experemental njs

.PHONY: start-all
start-all: build ## Start all docker compose services
	docker compose up -d

.PHONY: reload-nginx
reload-nginx: build start-all ## Reload nginx
	docker compose stop nginx && docker compose start nginx && docker compose logs -f nginx

