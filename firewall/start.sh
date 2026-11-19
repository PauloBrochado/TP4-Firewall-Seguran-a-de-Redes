#!/bin/bash
# TP4 - Arranque da firewall (corre dentro do container tp4-firewall).
#
# 1. Envia todo o trafego encaminhado (FORWARD) para a NFQUEUE 0.
#    Sem --queue-bypass: se nenhum programa estiver a ler a fila, o kernel
#    descarta os pacotes (fail-closed).
# 2. Corre o firewall.py e, se ele terminar, volta a lanca-lo ao fim de 5 s.
#    Durante esses 5 s nao ha decisoes, por isso o trafego e descartado.

# -C verifica se a regra ja existe, para nao a duplicar
iptables -C FORWARD -j NFQUEUE --queue-num 0 2> /dev/null || \
    iptables -A FORWARD -j NFQUEUE --queue-num 0

while true; do
    python3 -u /app/firewall.py
    codigo=$?
    echo "[start.sh] $(date -u +%Y-%m-%dT%H:%M:%SZ) firewall.py terminou (codigo $codigo)." \
         "Trafego descartado ate reiniciar. A reiniciar em 5 s..."
    sleep 5
done
