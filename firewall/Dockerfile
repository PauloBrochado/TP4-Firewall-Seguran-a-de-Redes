# Imagem da firewall: a mesma imagem SEED das aulas + NetfilterQueue.
# O NetfilterQueue e uma extensao em C, por isso precisa de compilador
# e da biblioteca libnetfilter-queue para ser instalado.
FROM handsonsecurity/seed-ubuntu:large

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev libnetfilter-queue-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install NetfilterQueue==1.1.0

WORKDIR /app
