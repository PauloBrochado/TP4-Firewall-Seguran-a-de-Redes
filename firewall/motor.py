"""Motor de decisao: junta a politica, os bloqueios temporarios e os detetores.

Ordem de decisao para cada pacote:
  1. Se a origem tem um bloqueio temporario ativo -> block.
  2. Corre todos os detetores. Cada detecao nova gera um evento "detection".
     Detetores em modo "detect_only" registam mas nao contam para a decisao.
  3. Se algum detetor propos uma acao, ganha a mais severa
     (block > drop > reject > limit > allow). Uma acao "block" cria um
     bloqueio temporario para o alvo.
  4. Se nenhum detetor disparou, aplica-se a acao por omissao da politica.
"""

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import eventos
from detetores.base import ACOES

SEVERIDADE = {acao: i for i, acao in enumerate(ACOES)}


@dataclass
class Decisao:
    acao: str
    motivo: str
    detetor: str
    ataque: Optional[str] = None
    contadores: Dict[str, Any] = field(default_factory=dict)


class Motor:
    def __init__(self, politica, detetores):
        self.politica = politica
        self.detetores = detetores
        self.intervalo_stats = politica["intervalo_estatisticas_s"]
        self.intervalo_enf = politica["intervalo_eventos_enforcement_s"]

        self.bloqueios = {}       # ip -> {"expira", "detetor", "ataque"}
        self.ultimo_enf = {}      # (detetor, origem) -> [instante do ultimo evento, pacotes desde entao]
        self.por_acao = Counter()
        self.por_ataque = Counter()
        agora = time.monotonic()
        self.ultimo_stats = agora
        self.ultima_limpeza = agora

    # ------------------------------------------------------------ decisao
    def decidir(self, ctx):
        self.tick(ctx.tempo_mono)
        src = ctx.ip.src

        # 1. bloqueio temporario ativo
        bloqueio = self.bloqueios.get(src)
        if bloqueio and bloqueio["expira"] > ctx.tempo_mono:
            restante = bloqueio["expira"] - ctx.tempo_mono
            return Decisao("block", f"bloqueio temporario ativo (faltam {restante:.0f} s)",
                           bloqueio["detetor"], bloqueio["ataque"],
                           {"segundos_restantes": round(restante, 1)})

        # 2. detetores
        candidatas = []
        for detetor in self.detetores:
            d = detetor.analisar(ctx)
            if d is None:
                continue
            if d.nova:
                eventos.deteccao(ctx, d, detetor.modo)
            if detetor.modo == "enforce":
                candidatas.append(d)

        # 3. a acao mais severa ganha
        if candidatas:
            pior = max(candidatas, key=lambda d: SEVERIDADE[d.acao])
            if pior.acao == "block":
                alvo = pior.alvo or src
                self.bloqueios[alvo] = {"expira": ctx.tempo_mono + pior.duracao_s,
                                        "detetor": pior.detetor, "ataque": pior.ataque}
            return Decisao(pior.acao, pior.motivo, pior.detetor, pior.ataque, pior.contadores)

        # 4. politica por omissao
        return Decisao(self.politica["acao_por_omissao"], "politica por omissao", "politica")

    # ------------------------------------------------------------ registo
    def registar(self, ctx, decisao):
        """Atualiza contadores e escreve eventos de enforcement (agregados por segundo)."""
        self.por_acao[decisao.acao] += 1
        if decisao.acao != "allow":
            self.por_ataque[decisao.ataque or "politica"] += 1
            chave = (decisao.detetor, ctx.ip.src)
            ultimo = self.ultimo_enf.get(chave)
            if ultimo is None or ctx.tempo_mono - ultimo[0] >= self.intervalo_enf:
                agregados = (ultimo[1] if ultimo else 0) + 1
                eventos.enforcement(ctx, decisao, agregados)
                self.ultimo_enf[chave] = [ctx.tempo_mono, 0]
            else:
                ultimo[1] += 1

    # ------------------------------------------------------------ manutencao
    def tick(self, agora):
        """Chamado a cada pacote e pelo ciclo principal (pelo menos 1 vez por segundo,
        mesmo sem trafego). Emite as estatisticas e faz a manutencao."""
        if agora - self.ultimo_stats >= self.intervalo_stats:
            eventos.estatisticas(self.intervalo_stats, self.por_acao, self.por_ataque)
            self.por_acao.clear()
            self.por_ataque.clear()
            self.ultimo_stats = agora
        self._manutencao(agora)

    def _manutencao(self, agora):
        """Cerca de 1 vez por segundo: expira bloqueios, alertas e estado antigo."""
        if agora - self.ultima_limpeza < 1:
            return
        self.ultima_limpeza = agora

        for ip in [ip for ip, b in self.bloqueios.items() if b["expira"] <= agora]:
            eventos.fim_bloqueio(ip, self.bloqueios.pop(ip))

        for detetor in self.detetores:
            for alvo in detetor.limpar(agora):
                eventos.deteccao_terminada(detetor, alvo)

        # esquecer origens sem enforcement ha mais de 10 s (limita a memoria,
        # importante com origens falsificadas aleatorias, ex. SYN flood)
        for chave in [c for c, u in self.ultimo_enf.items() if agora - u[0] > 10]:
            del self.ultimo_enf[chave]
