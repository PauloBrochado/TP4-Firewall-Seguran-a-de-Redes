"""Detetor de EXEMPLO (nao e um ataque das aulas).

Serve de modelo para os detetores verdadeiros. Mostra o padrao mais comum:
um contador deslizante por origem (rolling counter) numa janela temporal.

  Indicador : mais de max_pacotes ICMP echo request da mesma origem em janela_s segundos
  Resposta  : limit (descarta so os pacotes em excesso, o resto passa)
  Fim       : o alerta termina quando a contagem na janela volta ao limite ou abaixo
"""

from collections import defaultdict, deque

from scapy.all import ICMP

from .base import Deteccao, Detetor

ECHO_REQUEST = 8


class ExemploIcmpRajada(Detetor):
    nome = "exemplo_icmp_rajada"
    ataque = "exemplo_icmp_rajada"

    def __init__(self, config):
        super().__init__(config)
        self.janela = config["janela_s"]
        self.maximo = config["max_pacotes"]
        self.historico = defaultdict(deque)   # origem -> instantes dos echo requests
        self.em_alerta = set()                # origens com alerta ativo

    def _esquecer_antigos(self, fila, agora):
        while fila and fila[0] < agora - self.janela:
            fila.popleft()

    def analisar(self, ctx):
        ip = ctx.ip
        if ICMP not in ip or ip[ICMP].type != ECHO_REQUEST:
            return None

        src = ip.src
        fila = self.historico[src]
        fila.append(ctx.tempo_mono)
        self._esquecer_antigos(fila, ctx.tempo_mono)

        if len(fila) <= self.maximo:
            return None

        nova = src not in self.em_alerta
        self.em_alerta.add(src)
        return Deteccao(
            detetor=self.nome,
            ataque=self.ataque,
            acao="limit",
            nova=nova,
            severidade="low",
            motivo=(f"{len(fila)} ICMP echo request de {src} em {self.janela} s "
                    f"(limite {self.maximo})"),
            contadores={
                "echo_requests_na_janela": len(fila),
                "limite": self.maximo,
                "janela_s": self.janela,
            },
        )

    def limpar(self, agora):
        terminados = []
        for src in list(self.historico):
            fila = self.historico[src]
            self._esquecer_antigos(fila, agora)
            if src in self.em_alerta and len(fila) <= self.maximo:
                self.em_alerta.discard(src)
                terminados.append(src)
            if not fila:
                del self.historico[src]
        return terminados
