.PHONY: all install build run test clean docker-build docker-run

all: test

install:
	python -m pip install -e .

build:
	python setup.py build

run:
	python -m sentinel.daemon.cli --simulate-attacks

test:
	python -m unittest discover -s tests -p "test_*.py" -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info *.db *.log *.jsonl

docker-build:
	docker build -t sentinel-nids-siem .

docker-run:
	docker run -it --rm sentinel-nids-siem
