.PHONY: help
help:
	@echo "Make targets for rsp-jupyter-client"
	@echo "make init - Set up dev environment"
	@echo "make update - Update pinned dependencies and run make init"
	@echo "make update-deps - Update pinned dependencies"
	@echo "make update-deps-no-hashes - Pin dependencies without hashes"

.PHONY: init
init:
	pip install --upgrade uv
	uv pip install pre-commit tox
	uv pip install --editable .
	uv pip install -r requirements/main.txt -r requirements/dev.txt
	rm -rf .tox
	pre-commit install

.PHONY: update
update: update-deps init

.PHONY: update-deps
update-deps:
	pip install --upgrade uv
	uv pip install pre-commit
	pre-commit autoupdate
	uv pip compile --upgrade --generate-hashes			\
	    --output-file requirements/main.txt requirements/main.in
	uv pip compile --upgrade --generate-hashes			\
	    --output-file requirements/dev.txt requirements/dev.in

# Useful for testing against a Git version of a dependency.
.PHONY: update-deps-no-hashes
update-deps-no-hashes:
	pip install --upgrade uv
	uv pip compile --upgrade					\
	    --output-file requirements/main.txt requirements/main.in
	uv pip compile --upgrade					\
	    --output-file requirements/dev.txt requirements/dev.in
