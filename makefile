.PHONY: set_veth clean_veth run test_ping build

set_veth:
	scripts/set_veth.sh

clean_veth:
	scripts/clean_veth.sh

run:
	scripts/run.sh

test_ping:
	scripts/test_ping.sh

build:
	@echo ">>> Building"
	gcc -O2 -Isrc $(wildcard src/*.c) -o filter -lnetfilter_queue
