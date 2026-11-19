"""Registo dos detetores disponiveis.

Para acrescentar um detetor: importar a classe aqui, junta-la a DISPONIVEIS
e acrescentar a sua configuracao em politica.json (secao "detetores").
"""

from .exemplo_icmp_rajada import ExemploIcmpRajada

DISPONIVEIS = {
    ExemploIcmpRajada.nome: ExemploIcmpRajada,
}


def carregar(politica):
    """Cria os detetores configurados em politica.json (exceto os que estao em modo "off")."""
    ativos = []
    for nome, config in politica["detetores"].items():
        if config.get("modo", "enforce") == "off":
            continue
        if nome not in DISPONIVEIS:
            raise ValueError(f"Detetor desconhecido em politica.json: {nome}")
        ativos.append(DISPONIVEIS[nome](config))
    return ativos
