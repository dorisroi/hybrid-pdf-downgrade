# One-command reproduction. On Windows without make, run the python lines directly.
PY ?= python3
IMAGE ?= hybridpdf-repro

.PHONY: reproduce reproduce-dss freeze-reference docker-build docker-reproduce docker-reproduce-dss

## E1-E9 + audit + C1, compare with results/reference, write REVIEWER_REPORT.md
reproduce:
	$(PY) reproduce.py

## as above, and re-validate this run's artifacts with EU DSS 6.5 (JDK 17 + dssval/target/lib)
reproduce-dss:
	$(PY) reproduce.py --with-dss

## maintainers only: pin the current numbers as the reference the paper was built from
freeze-reference:
	$(PY) reproduce.py --freeze-reference

docker-build:
	docker build -t $(IMAGE) .

docker-reproduce: docker-build
	mkdir -p results/reproduce
	docker run --rm -v "$(CURDIR)/results/reproduce:/work/results/reproduce" $(IMAGE)

docker-reproduce-dss:
	docker build --build-arg WITH_DSS=1 -t $(IMAGE)-dss .
	mkdir -p results/reproduce
	docker run --rm -v "$(CURDIR)/results/reproduce:/work/results/reproduce" $(IMAGE)-dss --with-dss
