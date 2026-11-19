"""Contrato entre o nucleo da firewall e os detetores.

Este e o ficheiro que todos os detetores usam. Define tres coisas:

  Contexto  - o que o nucleo entrega ao detetor (pacote + interface + tempo)
  Deteccao  - o que o detetor devolve quando dispara
  Detetor   - a classe base de onde cada detetor herda

Para criar um detetor novo: copiar detetores/exemplo_icmp_rajada.py,
mudar o nome/ataque, escrever a logica em analisar() e limpar(), e registar
a classe em detetores/__init__.py e a configuracao em politica.json.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from scapy.all import TCP, UDP

PROTOCOLOS = {1: "icmp", 6: "tcp", 17: "udp"}

# Acoes possiveis, por ordem crescente de severidade.
# Quando varios detetores disparam no mesmo pacote, ganha a mais severa.
ACOES = ("allow", "limit", "reject", "drop", "block")


@dataclass
class Contexto:
    """Tudo o que o nucleo sabe sobre um pacote, entregue a cada detetor."""
    ip: Any               # pacote Scapy a partir da camada IP (ip.src, ip[TCP].seq, ...)
    tempo_utc: str        # para os eventos (ISO 8601, UTC, milissegundos)
    tempo_mono: float     # relogio monotonico, para janelas e duracoes
    if_entrada: str       # interface por onde o pacote entrou na firewall (ex. eth0)
    if_saida: str         # interface por onde vai sair
    zona_entrada: str     # zona da interface de entrada (ex. "clientes")
    zona_saida: str       # zona da interface de saida (ex. "servidores")

    def trafego(self) -> Dict[str, Any]:
        """Campos 'Traffic' do evento (secao 6.2 do enunciado)."""
        ip = self.ip
        t = {
            "src": ip.src,
            "dst": ip.dst,
            "proto": PROTOCOLOS.get(ip.proto, str(ip.proto)),
            "in_if": self.if_entrada,
            "out_if": self.if_saida,
            "direction": f"{self.zona_entrada}->{self.zona_saida}",
        }
        if TCP in ip:
            t["sport"] = ip[TCP].sport
            t["dport"] = ip[TCP].dport
            t["flags"] = str(ip[TCP].flags)
        elif UDP in ip:
            t["sport"] = ip[UDP].sport
            t["dport"] = ip[UDP].dport
        return t


@dataclass
class Deteccao:
    """O que um detetor devolve quando dispara."""
    detetor: str                  # nome do detetor
    ataque: str                   # nome do ataque, com a terminologia das aulas
    motivo: str                   # frase que explica porque disparou
    acao: str                     # acao proposta, uma de ACOES
    contadores: Dict[str, Any] = field(default_factory=dict)  # valores que justificam
    nova: bool = True             # True so no primeiro pacote de um alerta (evita inundar o log)
    severidade: str = "medium"    # low / medium / high
    alvo: Optional[str] = None    # IP a bloquear (acao "block"); por omissao, a origem
    duracao_s: float = 0          # duracao do bloqueio temporario (acao "block")


class Detetor:
    """Classe base. Cada detetor guarda o seu proprio estado (contadores, janelas, sessoes)."""
    nome = "base"
    ataque = "nenhum"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # "enforce": a acao proposta e aplicada
        # "detect_only": regista a detecao mas deixa passar (condicao nao mitigada)
        self.modo = config.get("modo", "enforce")

    def analisar(self, ctx: Contexto) -> Optional[Deteccao]:
        """Chamado para cada pacote. Devolve None ou uma Deteccao."""
        raise NotImplementedError

    def limpar(self, agora_mono: float) -> List[str]:
        """Chamado cerca de 1 vez por segundo.

        Deve esquecer estado antigo (para a memoria nao crescer sem limite)
        e devolver a lista de alvos cujo alerta terminou.
        """
        return []
