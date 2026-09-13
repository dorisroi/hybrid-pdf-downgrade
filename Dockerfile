# Reproduction image.
#   docker build -t hybridpdf-repro .
#   docker run --rm -v "$PWD/results/reproduce:/work/results/reproduce" hybridpdf-repro
# With the DSS 6.5 cross-check (adds a JDK and resolves DSS from Maven Central):
#   docker build --build-arg WITH_DSS=1 -t hybridpdf-repro-dss .
#   docker run --rm -v "$PWD/results/reproduce:/work/results/reproduce" hybridpdf-repro-dss --with-dss
FROM python:3.13-slim

ARG WITH_DSS=0
ENV PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /work

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN if [ "$WITH_DSS" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless maven \
      && rm -rf /var/lib/apt/lists/*; \
    fi
COPY dssval/pom.xml dssval/pom.xml
RUN if [ "$WITH_DSS" = "1" ]; then \
      mvn -q -f dssval/pom.xml dependency:copy-dependencies -DoutputDirectory=target/lib; \
    fi

COPY . .
ENTRYPOINT ["python", "reproduce.py"]
