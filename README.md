# TP4 — Firewall programável (base do laboratório)

Base do laboratório: topologia, firewall Python com NFQUEUE, núcleo modular e um detetor de exemplo.
A explicação completa de tudo (conceitos, decisões, testes) está em [`docs/EXPLICACAO-BASE.md`](docs/EXPLICACAO-BASE.md).

## Requisitos

- VM SEED Ubuntu 20.04 **x86_64** (confirmar com `uname -m`; em ARM ainda não foi testado)
- Docker e `docker-compose` (com hífen) da VM das aulas, sem atualizar
- Imagem `handsonsecurity/seed-ubuntu:large` (já vem na VM)
- Recomendado: **4 GB de RAM** na VM

## Pôr a correr (primeira vez)

```bash
# descompactar para ~/tp4
cd ~/tp4
chmod +x setup-host.sh
docker-compose build          # cria a imagem da firewall (alguns minutos, precisa de internet)
docker-compose up -d
sudo ./setup-host.sh          # exceção no iptables da VM (ver docs, secção 4.3)
```

## Depois de reiniciar a VM

```bash
cd ~/tp4
docker-compose up -d
sudo ./setup-host.sh          # obrigatório: as regras perdem-se no reboot
```

## Verificar que está tudo bem

```bash
docker ps                                                      # 4 containers tp4-* em "Up"
docker exec tp4-cliente ping -c 3 10.44.30.10                  # ttl=63 (um salto: a firewall)
docker exec tp4-cliente curl -s -m 3 http://10.44.30.10 || echo FALHOU   # "TP4 servidor OK"
docker logs tp4-firewall | head -3                             # zonas, detetores e "a escutar a NFQUEUE 0"
```

## Topologia

| Container | IP | Papel |
|---|---|---|
| `tp4-cliente` | 10.44.10.10 | Tráfego legítimo |
| `tp4-atacante` | 10.44.10.20 | Ataques (pasta `ataques/` montada em `/ataques`) |
| `tp4-firewall` | 10.44.10.254 (eth0) / 10.44.30.254 (eth1) | Encaminha e decide |
| `tp4-servidor` | 10.44.30.10 | HTTP :80 e Telnet :23 |

## Estrutura

```
docker-compose.yml     topologia
setup-host.sh          exceção no iptables da VM (sudo, após cada reboot)
ataques/               scripts de ataque
logs/                  eventos.jsonl e trial_atual (gerados ao correr)
docs/                  documentação
firewall/
  Dockerfile           imagem SEED + NetfilterQueue 1.1.0
  start.sh             regra NFQUEUE + reinício automático do Python
  firewall.py          lê a fila e aplica o veredito
  motor.py             ordem de decisão, bloqueios, contadores
  eventos.py           eventos JSON
  politica.json        política, zonas e configuração dos detetores
  detetores/
    base.py            contrato núcleo <-> detetores
    __init__.py        registo dos detetores
    exemplo_icmp_rajada.py   detetor-modelo (não é um ataque das aulas)
```

## Fazer um ensaio

```bash
echo "T01-nome-do-ensaio" > ~/tp4/logs/trial_atual
# ... correr o ataque e o tráfego legítimo ...
grep T01 ~/tp4/logs/eventos.jsonl
```

## Acrescentar um detetor

1. Copiar `firewall/detetores/exemplo_icmp_rajada.py` para um ficheiro novo.
2. Mudar `nome` e `ataque` e escrever `analisar()` e `limpar()`.
3. Registar a classe em `firewall/detetores/__init__.py`.
4. Acrescentar a configuração em `firewall/politica.json` (`"modo": "enforce" | "detect_only" | "off"`).
5. `docker-compose restart firewall`

Detalhes na secção 6.8 de `docs/EXPLICACAO-BASE.md`.

## Uso de IA

Esta base foi desenvolvida com a assistência do Claude (Anthropic) e validada com os testes descritos em `docs/EXPLICACAO-BASE.md`, secção 7.
