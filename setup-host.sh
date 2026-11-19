#!/bin/bash
# TP4 - Preparacao do host (VM SEED). Correr com sudo DEPOIS de "docker-compose up -d".
#
# Problema: com bridge-nf-call-iptables=1, o trafego dentro de cada bridge passa pelo
# iptables da VM. As regras de isolamento do Docker para redes "internal" descartam
# pacotes cujo destino esta fora da sub-rede da bridge (ex.: cliente -> 10.44.30.10),
# antes de chegarem a firewall.
#
# Solucao: aceitar apenas o trafego que entra e sai pela MESMA bridge.
#   - cliente -> firewall (br-tp4-cli) e firewall -> servidor (br-tp4-srv) passam.
#   - Trafego que tente saltar diretamente de uma bridge para a outra pelo host
#     continua a ser descartado pelo Docker (sem bypass da firewall).
#   - As redes continuam "internal": sem saida para fora da VM.
#
# As regras da DOCKER-USER perdem-se ao reiniciar a VM. Voltar a correr este script.

set -e

for BR in br-tp4-cli br-tp4-srv; do
    if ! ip link show "$BR" > /dev/null 2>&1; then
        echo "ERRO: a bridge $BR nao existe. Correr primeiro: docker-compose up -d"
        exit 1
    fi
    # -C verifica se a regra ja existe, para nao a duplicar
    if ! iptables -C DOCKER-USER -i "$BR" -o "$BR" -j ACCEPT 2> /dev/null; then
        iptables -I DOCKER-USER -i "$BR" -o "$BR" -j ACCEPT
        echo "Regra adicionada: $BR -> $BR ACCEPT"
    else
        echo "Regra ja existia: $BR -> $BR ACCEPT"
    fi
done

echo
iptables -L DOCKER-USER -v -n
