"""Telemetria: formato e escrita dos eventos JSON.

Cada evento e uma linha JSON em /logs/eventos.jsonl. Campos comuns a todos:
  time      timestamp UTC com milissegundos (ex. 2026-11-19T10:07:59.580+00:00)
  trial_id  identificador do ensaio em curso (lido de /logs/trial_atual)
  type      tipo de evento (ver abaixo)

Tipos de evento:
  detection        um detetor disparou (attack, detector, severity, mode,
                   traffic, reason, proposed_action, counters)
  detection_clear  o alerta de um detetor terminou (attack, detector, target)
  enforcement      a firewall aplicou uma acao diferente de allow (attack,
                   detector, traffic, decision, reason, counters). No maximo
                   1 evento por segundo por (detetor, origem). O contador
                   pacotes_agregados diz quantos pacotes esse evento representa.
  traffic_stats    contagens por acao e por ataque nos ultimos N segundos
                   (volume de trafego allowed vs blocked/limited)
  error            erro interno da firewall

O resultado de cada ensaio (stopped / reduced / detected_only / not_detected /
benign) NAO e decidido pelos detetores. Fica num evento "trial_outcome"
escrito pelo executor de ensaios depois de avaliar a metrica de sucesso.

Os eventos de detection e de enforcement estao separados de proposito: o
enunciado pede para se ver se a acao se seguiu ao alerta.
"""

import json
import os
from datetime import datetime, timezone

LOG_FILE = "/logs/eventos.jsonl"
TRIAL_FILE = "/logs/trial_atual"

_ficheiro = None
_trial = {"mtime": None, "valor": "sem-ensaio"}


def agora_utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def trial_atual():
    """Le o ensaio atual de /logs/trial_atual (so volta a ler se o ficheiro mudou)."""
    try:
        mtime = os.path.getmtime(TRIAL_FILE)
    except OSError:
        return "sem-ensaio"
    if mtime != _trial["mtime"]:
        with open(TRIAL_FILE) as f:
            _trial["valor"] = f.read().strip() or "sem-ensaio"
        _trial["mtime"] = mtime
    return _trial["valor"]


def emitir(tipo, **campos):
    global _ficheiro
    if _ficheiro is None:
        _ficheiro = open(LOG_FILE, "a", buffering=1)   # escreve linha a linha
    evento = {"time": agora_utc(), "trial_id": trial_atual(), "type": tipo}
    evento.update(campos)
    linha = json.dumps(evento)
    _ficheiro.write(linha + "\n")
    print(linha, flush=True)


def deteccao(ctx, d, modo):
    emitir("detection",
           attack=d.ataque, detector=d.detetor, severity=d.severidade, mode=modo,
           traffic=ctx.trafego(), reason=d.motivo, proposed_action=d.acao,
           counters=d.contadores)


def deteccao_terminada(detetor, alvo):
    emitir("detection_clear",
           attack=detetor.ataque, detector=detetor.nome, target=alvo,
           reason="indicador voltou abaixo do limite")


def enforcement(ctx, decisao, agregados):
    contadores = dict(decisao.contadores)
    contadores["pacotes_agregados"] = agregados
    emitir("enforcement",
           attack=decisao.ataque, detector=decisao.detetor, traffic=ctx.trafego(),
           decision=decisao.acao, reason=decisao.motivo, counters=contadores)


def fim_bloqueio(ip, bloqueio):
    emitir("enforcement",
           attack=bloqueio["ataque"], detector=bloqueio["detetor"],
           traffic={"src": ip}, decision="unblock",
           reason="fim do bloqueio temporario", counters={})


def estatisticas(janela_s, por_acao, por_ataque):
    emitir("traffic_stats", window_s=janela_s,
           counters={"by_decision": dict(por_acao), "by_attack": dict(por_ataque)})


def erro(mensagem):
    emitir("error", reason=mensagem)
