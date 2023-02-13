test: script1

script1:
	./test-scripts/script1.sh

unit:
	python3 -m unit-tests.sniffer-test

run:
	sudo python3 backend.py
