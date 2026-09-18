# lua-resty-surge
#
# Tests and benchmarks run in Docker (docker/Dockerfile.test) on
# openresty/openresty:1.31.1.1-3-jammy. Nothing is installed on the host.

IMAGE ?= lua-resty-surge/harness:latest
OPENRESTY_IMAGE ?= openresty/openresty:1.31.1.1-3-jammy
RUN := docker run --rm -v $(CURDIR):/work -w /work $(IMAGE)

.PHONY: image image-if-missing test test-unit smoke feeds bench microbench radix shell version

image:
	docker build -t $(IMAGE) --build-arg OPENRESTY_IMAGE=$(OPENRESTY_IMAGE) -f docker/Dockerfile.test docker

image-if-missing:
	@docker image inspect $(IMAGE) >/dev/null 2>&1 || $(MAKE) image

version: | image-if-missing
	$(RUN) openresty -v

test-unit: | image-if-missing
	$(RUN) busted spec

smoke: | image-if-missing
	$(RUN) sh t/smoke.sh

feeds: | image-if-missing
	$(RUN) sh t/feeds.sh

bench: | image-if-missing
	$(RUN) sh bench/protect.sh

radix: | image-if-missing
	$(RUN) resty bench/radix.lua

microbench: | image-if-missing
	$(RUN) resty bench/microbench.lua

test: test-unit smoke feeds

shell: | image-if-missing
	docker run --rm -it -v $(CURDIR):/work -w /work $(IMAGE)
