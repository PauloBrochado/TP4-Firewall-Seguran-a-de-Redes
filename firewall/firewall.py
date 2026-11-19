#!/usr/bin/env python3
"""TP4 - Firewall programavel - ponto de entrada.

Caminho de um pacote:
  kernel (iptables FORWARD -> NFQUEUE 0) -> ciclo select() -> tratar_pacote() -> Motor.decidir()
  -> detetores -> decisao -> veredito accept/drop devolvido ao kernel

Modulos:
  firewall.py          leitura da fila, contexto do pacote, veredito
  motor.py             ordem de decisao, bloqueios temporarios, contadores
  eventos.py           formato e escrita dos eventos JSON
  detetores/base.py    contrato entre o nucleo e os detetores
  detetores/*.py       um ficheiro por detetor
  politica.json        politica por omissao, zonas e configuracao dos detetores
"""

import ipaddress
import json
import select
import socket
import subprocess
import time

from netfilterqueue import NetfilterQueue
from scapy.all import IP

import eventos
from detetores import carregar
from detetores.base import Contexto
from motor import Motor

QUEUE_NUM = 0
POLITICA = "/app/politica.json"

_nomes_if = {}


def nome_interface(indice):
    """Converte o indice da interface (dado pelo kernel) no nome (ex. eth0)."""
    if indice not in _nomes_if:
        try:
            _nomes_if[indice] = socket.if_indextoname(indice)
        except OSError:
            _nomes_if[indice] = "?"
    return _nomes_if[indice]


def mapa_zonas(zonas):
    """Associa cada interface da firewall a uma zona, a partir do seu endereco IP."""
    saida = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                           capture_output=True, text=True).stdout
    mapa = {}
    for linha in saida.splitlines():
        partes = linha.split()            # ex.: 2: eth0 inet 10.44.10.254/24 ...
        interface, endereco = partes[1], partes[3]
        ip_interface = ipaddress.ip_interface(endereco).ip
        for zona, rede in zonas.items():
            if ip_interface in ipaddress.ip_network(rede):
                mapa[interface] = zona
    return mapa


def main():
    with open(POLITICA) as f:
        politica = json.load(f)
    detetores = carregar(politica)
    motor = Motor(politica, detetores)
    zonas = mapa_zonas(politica["zonas"])

    print(f"Zonas: {zonas}", flush=True)
    print("Detetores: " + ", ".join(f"{d.nome} ({d.modo})" for d in detetores), flush=True)

    def tratar_pacote(pkt):
        try:
            if_entrada = nome_interface(pkt.indev)
            if_saida = nome_interface(pkt.outdev)
            ctx = Contexto(
                ip=IP(pkt.get_payload()),
                tempo_utc=eventos.agora_utc(),
                tempo_mono=time.monotonic(),
                if_entrada=if_entrada,
                if_saida=if_saida,
                zona_entrada=zonas.get(if_entrada, "?"),
                zona_saida=zonas.get(if_saida, "?"),
            )
            decisao = motor.decidir(ctx)
            motor.registar(ctx, decisao)
        except Exception as e:
            # Fail-closed: um erro interno descarta o pacote e fica registado
            eventos.erro(f"{type(e).__name__}: {e}")
            pkt.drop()
            return

        if decisao.acao == "allow":
            pkt.accept()
        else:
            # limit, drop e block descartam o pacote.
            # TODO (nucleo): "reject" deve enviar TCP RST / ICMP unreachable a origem.
            pkt.drop()

    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, tratar_pacote)
    fila = socket.fromfd(nfq.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    print(f"Firewall a escutar a NFQUEUE {QUEUE_NUM}", flush=True)

    # Ciclo principal (uma so thread): espera por pacotes no maximo 1 s.
    # Se chegarem, trata-os todos. Em qualquer caso chama motor.tick(), para
    # as estatisticas e o fim de alertas/bloqueios acontecerem mesmo sem trafego.
    try:
        while True:
            pronto, _, _ = select.select([fila], [], [], 1.0)
            if pronto:
                nfq.run(block=False)
            motor.tick(time.monotonic())
    except KeyboardInterrupt:
        pass
    finally:
        fila.close()
        nfq.unbind()


if __name__ == "__main__":
    main()
