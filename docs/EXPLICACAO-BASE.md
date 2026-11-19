# TP4 — Explicação completa da base do laboratório

Este documento explica **tudo o que foi feito** para montar a base do TP4, **porque foi feito assim** e **o que cada teste provou**.
Foi escrito para quem não acompanhou a montagem (ou acompanhou e ficou perdido). Não é preciso saber nada de antemão.

Sugestão de leitura:
- Para perceber a ideia geral, lê as secções 1, 2 e 3.
- Para perceber cada passo, lê as secções 4 a 6, pela ordem.
- Antes da oral, lê as secções 9 e 11.

---

## Índice

1. [Resumo em 1 minuto](#1-resumo-em-1-minuto)
2. [Conceitos que precisas de saber](#2-conceitos-que-precisas-de-saber)
3. [A topologia e porque é assim](#3-a-topologia-e-porque-é-assim)
4. [Passo 1 — A rede](#4-passo-1--a-rede)
5. [Passo 2 — Pôr os pacotes a passar pelo Python](#5-passo-2--pôr-os-pacotes-a-passar-pelo-python)
6. [Passo 3 — Organizar o código para o grupo](#6-passo-3--organizar-o-código-para-o-grupo)
7. [Os testes feitos e o que provam](#7-os-testes-feitos-e-o-que-provam)
8. [Comandos do dia a dia](#8-comandos-do-dia-a-dia)
9. [Tabela de decisões](#9-tabela-de-decisões)
10. [O que ainda falta e limitações conhecidas](#10-o-que-ainda-falta-e-limitações-conhecidas)
11. [Perguntas prováveis na oral](#11-perguntas-prováveis-na-oral)
12. [Ligação ao relatório](#12-ligação-ao-relatório)

---

## 1. Resumo em 1 minuto

O TP4 pede uma **firewall feita por nós** que deteta e trava os ataques do TP1 e do TP2, e que regista tudo para se ver num dashboard.

Até agora foi montada **a base** onde tudo isso vai encaixar:

- **Uma rede de laboratório** com 4 máquinas (containers Docker): um cliente legítimo, um atacante, a firewall e um servidor.
- **A firewall no meio**, de forma que todo o tráfego entre o lado dos clientes e o lado do servidor **é obrigado** a passar por ela. Isto foi testado.
- **Um programa Python** na firewall que recebe **cada pacote**, decide se passa ou não e **regista a decisão em JSON**.
- **Uma estrutura de código** onde cada colega acrescenta o detetor do seu ataque **sem mexer no código dos outros**.
- **Um detetor de exemplo** (não é um ataque das aulas) que mostra como um detetor funciona.

Ainda **não** há detetores dos ataques reais, nem Grafana. Isso vem a seguir e já tem onde encaixar.

---

## 2. Conceitos que precisas de saber

Se já sabes estes conceitos, salta esta secção.

### Container e Docker
Um **container** é uma "mini-máquina" isolada que corre dentro da VM. Cada container tem o seu próprio IP, as suas interfaces de rede e os seus processos. Nas aulas (TP1, TP2, TP3) já usaram containers, como o `seed-attacker` e o `victim-10.9.0.5`.

O **docker-compose** é a ferramenta que cria vários containers e as redes entre eles a partir de um ficheiro de texto, o `docker-compose.yml`. Um comando (`docker-compose up -d`) monta o laboratório todo.

### Bridge (rede Docker)
Cada rede do Docker é uma **bridge**, ou seja, um **switch virtual** dentro da VM. Os containers ligados à mesma bridge estão na mesma LAN.

Temos duas bridges:
- `br-tp4-cli`, a rede dos clientes
- `br-tp4-srv`, a rede dos servidores

### Router e encaminhamento (forwarding)
Um **router** é uma máquina com interfaces em **duas ou mais redes** que passa pacotes de uma rede para a outra. No Linux, isto liga-se com `net.ipv4.ip_forward=1`.

A nossa firewall **é um router**: tem uma perna em cada rede e passa os pacotes de um lado para o outro. Como é ela que os passa, também pode decidir **não** os passar. É essa a ideia de uma firewall.

### Rota por omissão (default route)
É a regra "se não sei para onde mandar este pacote, mando-o para este router". No cliente, a rota por omissão aponta para a firewall (`10.44.10.254`). Assim, tudo o que o cliente manda para fora da sua rede vai **primeiro para a firewall**.

### iptables e a cadeia FORWARD
O **iptables** é o sistema de regras de rede do kernel Linux. As regras estão organizadas em **cadeias**. A que nos interessa é a **FORWARD**, por onde passam **os pacotes que o router está a encaminhar** de uma rede para outra.

Atenção a um pormenor importante: há **dois** iptables diferentes no nosso sistema.
- O iptables **da firewall** (dentro do container `tp4-firewall`), onde está a nossa regra.
- O iptables **da VM** (o "host"), onde o Docker coloca as suas próprias regras. Foi aqui que apareceu o primeiro problema (secção 4.3).

### NFQUEUE e NetfilterQueue
Normalmente o kernel decide sozinho o que fazer a cada pacote (aceitar ou descartar). Com uma regra `-j NFQUEUE`, o kernel **pára o pacote** e coloca-o numa **fila**. Fica à espera que um programa em espaço de utilizador diga "aceita" ou "descarta".

O **NetfilterQueue** é a biblioteca Python que lê essa fila. É assim que **o nosso código Python** passa a ser quem decide.

### Scapy
Biblioteca Python para **ler e construir pacotes**. Já a usaram no TP1 e no TP2 para forjar pacotes. Aqui usamo-la para **interpretar** os bytes que vêm da fila: `IP(bytes)` dá um objeto onde se lê `ip.src`, `ip[TCP].seq`, etc.

### JSON e JSONL
**JSON** é um formato de texto para dados estruturados: `{"campo": "valor"}`. **JSONL** (JSON Lines) é um ficheiro com **um objeto JSON por linha**. É o formato que ferramentas como o Loki/Grafana leem facilmente. O nosso ficheiro de eventos é `logs/eventos.jsonl`.

### Fail-closed vs fail-open
O que acontece quando a firewall falha (por exemplo, o programa Python morre):
- **Fail-closed:** o tráfego **pára**. É mais seguro, porque um atacante não passa, mas os serviços ficam indisponíveis.
- **Fail-open:** o tráfego **passa sem controlo**. É mais disponível, mas fica sem proteção.

A nossa firewall é **fail-closed**, e isso foi testado.

### Relógio UTC vs relógio monotónico
- **UTC:** hora "real" com fuso horário. Usa-se nos eventos para correlacionar o que aconteceu e quando (o enunciado exige timezone).
- **Monotónico:** um contador que só anda para a frente e nunca salta (mesmo que alguém acerte a hora do sistema). Usa-se para **medir janelas e durações** ("quantos pacotes nos últimos 5 segundos?").

### PID 1
Dentro de um container, o primeiro processo tem o número **1** (PID 1). O Linux trata o PID 1 de forma especial: **ignora sinais** como o `kill`/`pkill`, a não ser que o programa os trate explicitamente. Isto causou o segundo problema (secção 5.4).

---

## 3. A topologia e porque é assim

### 3.1 O diagrama

```
             REDE DOS CLIENTES                              REDE DOS SERVIDORES
           (lan-clientes, 10.44.10.0/24)                 (lan-servidores, 10.44.30.0/24)
                bridge br-tp4-cli                              bridge br-tp4-srv

  ┌──────────────┐                                                       ┌──────────────┐
  │   cliente    │──┐                                                ┌──│   servidor   │
  │ 10.44.10.10  │  │                ┌──────────────────┐            │  │ 10.44.30.10  │
  └──────────────┘  │                │     firewall     │            │  │ HTTP :80     │
                    ├────── eth0 ────│ .254        .254 │──── eth1 ──┤  │ Telnet :23   │
  ┌──────────────┐  │  10.44.10.254  │  iptables FORWARD│ 10.44.30.254  └──────────────┘
  │   atacante   │──┘                │   -> NFQUEUE 0   │            │
  │ 10.44.10.20  │                   │   -> firewall.py │            └── (mais tarde:
  └──────────────┘                   └────────┬─────────┘                 atacante 2)
                                              │
                                      logs/eventos.jsonl
                                      (mais tarde: Grafana)
```

| Máquina | Container | IP | Rota por omissão | Papel |
|---|---|---|---|---|
| Cliente | `tp4-cliente` | 10.44.10.10 | 10.44.10.254 (firewall) | Gera tráfego legítimo |
| Atacante | `tp4-atacante` | 10.44.10.20 | 10.44.10.254 (firewall) | Lança os ataques |
| Firewall | `tp4-firewall` | 10.44.10.254 (eth0) e 10.44.30.254 (eth1) | (não precisa) | Encaminha e decide |
| Servidor | `tp4-servidor` | 10.44.30.10 | 10.44.30.254 (firewall) | Serviços protegidos (HTTP, Telnet) |

### 3.2 Porque partimos do Labsetup do TP3

O laboratório do TP3 já tinha **um router entre duas redes** (o `server-router`, com 10.9.0.11 e 192.168.60.11). Isto é praticamente a forma que o TP4 precisa: basta pôr a firewall no lugar do router.

No TP1 e no TP2 estava **tudo na mesma rede** (10.9.0.0/24), sem ninguém no meio. Uma firewall só consegue decidir sobre pacotes que **passam por ela**, por isso esse layout não servia.

### 3.3 Porque é que o atacante está na mesma rede do cliente

Esta é a decisão mais importante da topologia. Vale a pena perceber bem.

Os ataques do TP2 (RST, hijacking, reverse shell) **só funcionam se o atacante conseguir ver o tráfego da vítima**. Nos vossos scripts do TP2 (`task_2.py`, `task_3.py`) os números de sequência (`seq=3916455654`) foram copiados do Wireshark, ou seja, o atacante estava a espiar a sessão Telnet. Sem esses números o ataque é impossível (teria de adivinhar um número de 32 bits).

Havia três opções:

| Opção | Ideia | Problema |
|---|---|---|
| **A** | Atacante numa rede separada (atrás de outra interface da firewall) | O atacante **não vê** o tráfego do cliente. Metade dos ataques ficam **impossíveis**, e os que restam são detetados só por chegarem pela interface "errada", o que é demasiado fácil |
| **B** ✅ | Atacante na **mesma rede** do cliente | Os ataques das aulas continuam válidos. A firewall é obrigada a detetá-los pelo **comportamento** (estado TCP, contadores), que é o que o enunciado valoriza |
| **C** | Tudo na mesma rede, com a firewall em modo "bridge" transparente | Mais difícil de montar e de explicar |

Para cada ataque, as duas perguntas são: **(1) o atacante precisa de ver o tráfego?** e **(2) o pacote falso passa pela firewall?**

| Ataque | Precisa de ver? | Opção A | Opção B | B + atacante 2 |
|---|---|---|---|---|
| ICMP spoofing (TP1) | Não | ✅ mas deteção trivial | ✅ | ✅ |
| Sniff-and-then-spoof (TP1) | Sim | ❌ impossível | ⚠️ a resposta falsa fica na rede A e **não passa** pela firewall | ✅ |
| Sniffing de passwords Telnet (TP1) | Sim | ❌ impossível | ⚠️ funciona mas é **indetetável** (sniffer passivo) | ⚠️ indetetável |
| SYN flood (TP2) | Não | ✅ | ✅ | ✅ |
| TCP RST (TP2) | Sim | ❌ impossível | ✅ (no sentido cliente→servidor) | ✅ |
| Session hijacking (TP2) | Sim | ❌ impossível | ✅ | ✅ |
| Reverse shell (TP2) | Sim (via hijacking) | ❌ impossível | ✅ a ligação de retorno passa pela firewall | ✅ |

**"Atacante 2"** é um segundo atacante que poderá ser colocado mais tarde **na rede do servidor**, para o cenário sniff-and-spoof. O cliente faz ping a um IP inexistente na rede do servidor, o atacante 2 vê o pedido e responde, e essa resposta falsa **é obrigada a atravessar a firewall**.

> ⚠️ **A confirmar com o professor:** se a hipótese "atacante na mesma LAN do cliente" é aceitável e como ele quer que tratemos o sniffing passivo.

### 3.4 Porque as redes são `internal: true`

No `docker-compose.yml`, as duas redes têm `internal: true`. Isto significa que **não têm saída para fora da VM** (sem internet).

Há duas vantagens:
- **Segurança:** o enunciado (secção 9) proíbe expor o laboratório e mandar ataques para fora.
- **Sem atalhos:** sem isto, cada container tinha uma rota para o "gateway do Docker" (o `.1` de cada rede) e o tráfego podia **contornar a firewall** pela VM. Foi exatamente isto que, no TP3, fez falhar o ping do Host U ao Host V.

### 3.5 Porque cada container só tem as permissões de que precisa

Nos Labsetup do professor os containers têm `cap_add: ALL` (todas as permissões de administrador). Nós demos só o necessário:

| Container | Permissões | Para quê |
|---|---|---|
| cliente, servidor | `NET_ADMIN` | Mudar a rota por omissão |
| atacante | `NET_ADMIN`, `NET_RAW` | Rotas e forjar pacotes com Scapy (raw sockets) |
| firewall | `NET_ADMIN`, `NET_RAW` | iptables, NFQUEUE, encaminhamento, tcpdump |

O enunciado (secção 9) pede para **documentar e limitar** os privilégios elevados, e o `CONTEXTO-TP4` pedia para evitar `privileged: true`.

### 3.6 Porque os IPs são 10.44.x.x

Foram propostos no `CONTEXTO-TP4` do grupo. São sub-redes que não colidem com as dos labs das aulas (10.9.0.0/24, 192.168.60.0/24), por isso os labs antigos e o TP4 podem coexistir na mesma VM. O `.254` para a firewall é uma convenção comum para routers e fica fácil de reconhecer.

---

## 4. Passo 1 — A rede

**Objetivo:** montar os 4 containers e provar que o tráfego entre as redes passa **obrigatoriamente** pela firewall. Nesta fase ainda não há código Python, a firewall só encaminha.

### 4.1 O que o `docker-compose.yml` faz (versão do passo 1)

Para cada container:
- `image: handsonsecurity/seed-ubuntu:large` — a mesma imagem das aulas (já traz Scapy, iptables, Telnet, tcpdump, nc).
- `networks:` com `ipv4_address` — liga o container a uma rede com um IP fixo.
- `command:` — o que o container corre ao arrancar:
  - cliente e atacante: `ip route replace default via 10.44.10.254` (rota para a firewall)
  - servidor: rota para `10.44.30.254`, arranca o Telnet (`openbsd-inetd`) e um servidor HTTP simples (`python3 -m http.server 80`) que responde `TP4 servidor OK`
  - firewall: `sysctls: net.ipv4.ip_forward=1` liga o encaminhamento

Usou-se `ip route replace` em vez de `ip route del` + `ip route add` (como no TP3) porque o `replace` funciona exista ou não uma rota antes. Nas redes `internal` o Docker não cria rota por omissão, por isso o `del` falhava.

Nas redes, `com.docker.network.bridge.name` dá um **nome fixo** às bridges (`br-tp4-cli` e `br-tp4-srv`). Sem isso o Docker inventa nomes como `br-5480ba2aa898`, que mudam sempre que a rede é recriada. O nome fixo é necessário para o script da secção 4.3.

### 4.2 O primeiro teste falhou

O ping do cliente ao servidor deu **100% de perda** e o curl ficou 4 minutos pendurado.

### 4.3 Problema 1: o Docker deitava os pacotes fora na VM

**Diagnóstico.** Listámos as regras de isolamento do Docker na VM (`sudo iptables -L DOCKER-ISOLATION-STAGE-1 -v -n`) antes e depois de um ping. O contador desta linha subiu de 10 para 13:

```
DROP  all  --  br-tp4-cli  *  0.0.0.0/0  !10.44.10.0/24
```

Lê-se assim: *"tudo o que entra pela bridge br-tp4-cli com destino **fora** de 10.44.10.0/24, descarta"*.

**Porque acontece.** A VM tem `bridge-nf-call-iptables = 1`. Isso faz com que **até o tráfego que só atravessa uma bridge** (do cliente para a firewall, dentro da mesma rede) passe pelo iptables **da VM**. O Docker, para isolar as redes `internal`, pôs lá a regra acima. O ping do cliente vai para 10.44.30.10, que não pertence a 10.44.10.0/24, por isso a VM matava-o **antes de chegar à firewall**.

Uma analogia: o cliente mete a carta no correio para a firewall, mas o carteiro (a VM) lê o destino final escrito no envelope, vê que é "para fora do bairro" e deita-a fora, porque o bairro é "fechado".

**A solução: `setup-host.sh`.** Havia duas opções:
- Tirar o `internal: true`. Funcionava, mas o laboratório ganhava saída para a internet. ❌
- **Abrir uma exceção mínima** na cadeia `DOCKER-USER` da VM, que o Docker avalia **antes** das suas regras de isolamento. ✅

O script acrescenta duas regras:

```bash
iptables -I DOCKER-USER -i br-tp4-cli -o br-tp4-cli -j ACCEPT
iptables -I DOCKER-USER -i br-tp4-srv -o br-tp4-srv -j ACCEPT
```

Isto significa: *"aceita o que entra e sai **pela mesma bridge**"*. Na prática:
- cliente → firewall (dentro da br-tp4-cli): ✅ passa
- firewall → servidor (dentro da br-tp4-srv): ✅ passa
- algo que tente saltar **diretamente** da br-tp4-cli para a br-tp4-srv pela VM (bypass): ❌ continua bloqueado pelo Docker
- saída para a internet: ❌ continua bloqueada (`internal: true`)

O script verifica se a regra já existe (`iptables -C`) antes de a criar, por isso pode ser corrido várias vezes sem duplicar.

> ⚠️ **As regras perdem-se quando a VM reinicia.** Depois de cada reboot é preciso correr `docker-compose up -d` e depois `sudo ./setup-host.sh`.

### 4.4 Os testes que passaram

| Teste | Resultado | O que prova |
|---|---|---|
| `ping` cliente → servidor | 3/3, `ttl=63` | Há comunicação. O TTL começa em 64 e cada router desconta 1: **63 = exatamente um salto**, a firewall |
| `curl` cliente → servidor | `TP4 servidor OK` | O serviço HTTP funciona através da firewall |
| `iptables -P FORWARD DROP` na firewall + ping | **100% perda** | Se a firewall bloqueia, **não há outro caminho**: não há bypass |
| `iptables -P FORWARD ACCEPT` + ping | volta a funcionar | O bloqueio era mesmo da firewall |

O facto de o ping ter resposta prova também que **as respostas do servidor passam pela firewall** (o servidor também tem a rota por omissão apontada para ela).

---

## 5. Passo 2 — Pôr os pacotes a passar pelo Python

**Objetivo:** cada pacote encaminhado é entregue ao nosso programa Python, que decide e regista.

### 5.1 O caminho de um pacote

```
cliente envia ping para 10.44.30.10
        │
        ▼
firewall recebe na eth0 ── kernel: "isto é para encaminhar" ── cadeia FORWARD
        │
        ▼
regra: iptables -A FORWARD -j NFQUEUE --queue-num 0
        │   (o kernel PÁRA o pacote e mete-o na fila 0)
        ▼
firewall.py lê a fila (NetfilterQueue) ── converte em objeto Scapy ── decide
        │
        ├── pkt.accept() ──► kernel continua: sai pela eth1 ──► servidor
        └── pkt.drop()   ──► kernel descarta o pacote
```

Ponto-chave para a oral: **a decisão é tomada no Python, mas é aplicada pelo kernel.** O Python só diz "aceita" ou "descarta" (o *veredito*).

### 5.2 Os ficheiros novos do passo 2

**`firewall/Dockerfile`** — cria uma imagem nova para a firewall:
- parte da mesma imagem SEED das aulas
- instala `build-essential`, `python3-dev` e `libnetfilter-queue-dev`, porque o NetfilterQueue é escrito em C e tem de ser **compilado** (a imagem original não tinha `gcc`)
- instala `NetfilterQueue==1.1.0`, com a **versão fixada**, como o `CONTEXTO-TP4` pedia (nada de "a mais recente", que pode mudar e partir tudo)

**`docker-compose.yml`** — a firewall passa a usar `build: ./firewall` (a imagem nova) e monta duas pastas:
- `./firewall:/app` — o código. Editas no host e o container vê logo, sem rebuild.
- `./logs:/logs` — os eventos JSON ficam acessíveis no host em `~/tp4/logs/`.

### 5.3 Fail-closed "de graça"

A regra NFQUEUE **não** tem a opção `--queue-bypass`. Sem ela, se nenhum programa estiver a ler a fila, **o kernel descarta os pacotes**. Ou seja, se o Python morrer, o tráfego pára. A firewall é fail-closed por construção.

### 5.4 Problema 2: o `pkill` não matava o Python (PID 1)

**O que aconteceu.** Para testar o fail-closed, matámos o Python com `pkill -f firewall.py`. O ping **continuou a funcionar**. O teste falhou.

**Porquê.** O Python estava a correr como **PID 1** do container. O Linux ignora o sinal do `pkill` para o PID 1 (ver secção 2), por isso o Python nem sentiu e continuou a decidir.

Ainda bem que testámos. Senão íamos dizer na oral "é fail-closed" sem o ter provado.

**A solução tem duas partes:**

1. **`init: true`** no `docker-compose.yml` (o que exigiu mudar para `version: "3.7"`). O Docker põe um mini-programa de arranque (`docker-init`) como PID 1, e o Python passa a ser um processo normal que obedece aos sinais. Confirmado com `ps -ef`:
   ```
   PID 1  /sbin/docker-init -- bash /app/start.sh
   PID 6  bash /app/start.sh
   PID 9  python3 -u /app/firewall.py
   ```

2. **`firewall/start.sh`**, o script de arranque da firewall:
   - cria a regra `FORWARD -> NFQUEUE 0` (só se ainda não existir)
   - corre o `firewall.py` dentro de um ciclo `while true`: se o Python morrer, escreve uma mensagem com a hora, **espera 5 segundos** e volta a lançá-lo

Os 5 segundos são de propósito. É a janela onde ninguém lê a fila, e por isso dá para **ver** o fail-closed num teste. Depois disso a firewall **recupera sozinha**.

### 5.5 Os testes que passaram

| Teste | Resultado | O que prova |
|---|---|---|
| ping/curl com a firewall Python | ✅ funcionam | Os pacotes passam pelo Python e voltam ao kernel |
| `pkill` + ping imediato | **100% perda** | **Fail-closed**: sem decisão, sem tráfego |
| esperar 5 s + ping | ✅ volta sozinho | **Recuperação automática** |
| `docker logs tp4-firewall \| grep start.sh` | `firewall.py terminou (codigo 143)` | A falha fica registada. 143 = 128 + 15 = morto por SIGTERM, o sinal do pkill |

**Observação de desempenho:** o RTT do ping passou de **~0,15 ms** (só o kernel) para **~3 ms** (com o Python). É o custo de cada pacote sair do kernel, ir ao Python e voltar. É um dado útil para a análise crítica e explica porque é que, mais à frente, num SYN flood, pode ser preciso passar os bloqueios para o kernel.

---

## 6. Passo 3 — Organizar o código para o grupo

**Objetivo:** cada colega deve conseguir escrever o detetor do seu ataque **sem mexer no código dos outros** e sem partir o núcleo.

### 6.1 A estrutura

```
~/tp4/
├── docker-compose.yml        topologia (containers, redes, IPs)
├── setup-host.sh             exceção no iptables da VM (correr com sudo após cada reboot)
├── instalar-passo3.sh        script que criou os ficheiros do passo 3 (pode ser apagado depois)
├── ataques/                  scripts de ataque (montado no atacante em /ataques)
├── logs/
│   ├── eventos.jsonl         todos os eventos, um JSON por linha
│   └── trial_atual           nome do ensaio em curso
└── firewall/
    ├── Dockerfile            imagem SEED + NetfilterQueue
    ├── start.sh              regra NFQUEUE + reinício automático do Python
    ├── firewall.py           lê a fila, monta o contexto, aplica o veredito
    ├── motor.py              decide (bloqueios → detetores → política)
    ├── eventos.py            formato e escrita dos eventos JSON
    ├── politica.json         configuração: política por omissão, zonas, detetores
    └── detetores/
        ├── base.py           O CONTRATO entre o núcleo e os detetores
        ├── __init__.py       lista dos detetores disponíveis
        └── exemplo_icmp_rajada.py   detetor-modelo
```

Cada ficheiro tem **uma só responsabilidade**. Isto ajuda na divisão do trabalho e na oral (o enunciado pede para explicar "main modules and their responsibilities").

### 6.2 `firewall.py` — o ponto de entrada

Faz três coisas:

**a) Arranque**
- lê o `politica.json`
- cria os detetores que lá estão configurados
- cria o `Motor`
- descobre que interface pertence a que zona (`mapa_zonas`): corre `ip -o -4 addr show`, vê que a `eth0` tem 10.44.10.254 (dentro de 10.44.10.0/24, logo zona "clientes") e que a `eth1` tem 10.44.30.254 (zona "servidores")

**b) Tratar cada pacote (`tratar_pacote`)**
- converte os bytes em Scapy: `IP(pkt.get_payload())`
- descobre a interface de entrada e de saída (`pkt.indev`, `pkt.outdev`). O kernel dá um número, que é convertido em nome (`eth0`)
- monta um **`Contexto`** com o pacote, as interfaces, as zonas e os dois relógios
- pede ao motor uma decisão e regista-a
- aplica o veredito: `allow` → `pkt.accept()`, qualquer outra coisa → `pkt.drop()`
- se houver **um erro inesperado** (por exemplo, um bug num detetor): descarta o pacote e escreve um evento `error`. Mantém a lógica fail-closed

**c) O ciclo principal**
```python
while True:
    pronto = select.select([fila], [], [], 1.0)   # espera por pacotes, no máximo 1 s
    if pronto:
        nfq.run(block=False)                       # trata todos os que chegaram
    motor.tick(time.monotonic())                   # trabalho periódico
```

Porque não simplesmente `nfq.run()`? Porque esse fica parado à espera de pacotes **para sempre**. Sem tráfego, nada mais acontecia: os alertas nunca fechavam e as estatísticas paravam. Descobrimos isto no primeiro teste do passo 3, quando faltou o evento `detection_clear`. Com o `select` com 1 segundo de limite, o programa **acorda pelo menos uma vez por segundo**, mesmo sem tráfego.

Tudo corre **numa só thread**, por isso não há problemas de concorrência (locks, condições de corrida) para explicar.

### 6.3 `detetores/base.py` — o contrato

É **o ficheiro mais importante para o grupo**. Define a "língua comum" entre o núcleo e os detetores.

**`Contexto`** — o que o núcleo entrega ao detetor, para cada pacote:

| Campo | Exemplo | Para quê |
|---|---|---|
| `ip` | objeto Scapy | Ler qualquer campo: `ip.src`, `ip[TCP].flags`, `ip[TCP].seq` |
| `tempo_utc` | `2026-11-19T10:24:13.402+00:00` | Para os eventos |
| `tempo_mono` | `12345.678` | Para janelas e durações |
| `if_entrada` / `if_saida` | `eth0` / `eth1` | Saber por onde veio e para onde vai |
| `zona_entrada` / `zona_saida` | `clientes` / `servidores` | O mesmo, com nomes legíveis |

Tem também o método `trafego()`, que devolve os campos de tráfego do evento (origem, destino, protocolo, portas, flags TCP, interfaces, direção). Isto cobre o campo "Traffic" da secção 6.2 do enunciado.

**`Deteccao`** — o que o detetor devolve quando dispara:

| Campo | Para quê |
|---|---|
| `detetor`, `ataque` | Identificar quem disparou e que ataque é (com o nome das aulas) |
| `motivo` | Frase legível: "21 ICMP echo request de 10.44.10.10 em 5 s (limite 20)" |
| `acao` | A ação proposta: `allow`, `limit`, `reject`, `drop` ou `block` |
| `contadores` | Os números que justificam a deteção |
| `nova` | `True` só no **primeiro** pacote de um alerta (ver 6.6) |
| `severidade` | low / medium / high |
| `alvo`, `duracao_s` | Para `block`: que IP bloquear e durante quanto tempo |

**`Detetor`** — a classe base. Cada detetor herda dela e escreve dois métodos:
- `analisar(ctx)` — chamado **para cada pacote**. Devolve `None` (não vi nada) ou uma `Deteccao`.
- `limpar(agora)` — chamado **cerca de 1 vez por segundo**. Esquece estado antigo (para a memória não crescer sem fim) e devolve a lista de alvos cujo alerta terminou.

Cada detetor também tem um **modo**, lido do `politica.json`:
- `enforce` — a ação proposta é aplicada
- `detect_only` — a deteção é registada, mas o pacote passa
- `off` — o detetor nem é carregado

**`ACOES`** — a lista das ações por ordem de severidade: `allow < limit < reject < drop < block`.

### 6.4 `motor.py` — quem decide

Para cada pacote, o `Motor.decidir(ctx)` segue **sempre esta ordem**:

1. **A origem tem um bloqueio temporário ativo?** Se sim, a decisão é `block` e os detetores nem são consultados.
2. **Corre todos os detetores.** Cada deteção **nova** gera um evento `detection`. Os detetores em `detect_only` registam mas não entram na decisão.
3. **Se algum detetor propôs uma ação, ganha a mais severa.** Se for `block`, cria um bloqueio temporário para o alvo (por omissão, o IP de origem).
4. **Se nenhum disparou**, aplica a ação por omissão da política (`allow`).

O ponto 3 é a **resolução de conflitos** que o enunciado pede no "policy model". Exemplo: se o detetor A diz `limit` e o B diz `drop`, o pacote é descartado.

O `Motor.registar(ctx, decisao)` atualiza os contadores e escreve os eventos de `enforcement` (ver 6.6).

O `Motor.tick(agora)` corre o trabalho periódico:
- a cada 5 s, emite as **estatísticas** (`traffic_stats`) e zera os contadores
- a cada ~1 s: termina os bloqueios que expiraram (evento `unblock`), pergunta a cada detetor se algum alerta terminou (evento `detection_clear`) e esquece entradas antigas da tabela de agregação (para a memória não explodir num SYN flood com milhares de origens falsas)

### 6.5 `politica.json` — a configuração

```json
{
  "acao_por_omissao": "allow",
  "zonas": { "clientes": "10.44.10.0/24", "servidores": "10.44.30.0/24" },
  "intervalo_estatisticas_s": 5,
  "intervalo_eventos_enforcement_s": 1,
  "detetores": {
    "exemplo_icmp_rajada": { "modo": "enforce", "janela_s": 5, "max_pacotes": 20 }
  }
}
```

Porque separar a configuração do código?
- Os **limites** (thresholds) mudam-se sem mexer no Python. Por exemplo, para testar falsos positivos com limites diferentes.
- Ligar e desligar um detetor (`enforce` / `detect_only` / `off`) é **uma linha**, o que dá jeito para o método de teste.
- Na oral e no relatório, a "política documentada" que o enunciado pede está **num só sítio**.

Depois de mudar o `politica.json`, faz `docker-compose restart firewall`.

> Ainda está `"acao_por_omissao": "allow"`. A política final (por exemplo, só deixar passar HTTP e Telnet para o servidor e bloquear o resto) é uma decisão a tomar com o grupo.

### 6.6 `eventos.py` — a telemetria

Todos os eventos são escritos em `logs/eventos.jsonl` (e também aparecem no `docker logs tp4-firewall`).

**Campos comuns a todos:**
- `time` — UTC com milissegundos, por exemplo `2026-11-19T10:24:13.402+00:00`
- `trial_id` — o ensaio em curso
- `type` — o tipo de evento

**Tipos de evento:**

| Tipo | Quando | Campos principais |
|---|---|---|
| `detection` | Um detetor dispara (1.º pacote do alerta) | attack, detector, severity, mode, traffic, reason, proposed_action, counters |
| `detection_clear` | O alerta termina | attack, detector, target |
| `enforcement` | A firewall aplica uma ação ≠ allow | attack, detector, traffic, decision, reason, counters (+ `pacotes_agregados`) |
| `traffic_stats` | A cada 5 s | contagens por decisão e por ataque |
| `error` | Erro interno | reason |

**Como isto cobre a secção 6.2 do enunciado:**

| Campo exigido | Onde está |
|---|---|
| Time (com timezone) | `time` |
| Attack | `attack` |
| Traffic (origem, destino, protocolo, portas, interface, direção) | `traffic` |
| Decision | `decision` (enforcement) / `proposed_action` (detection) |
| Reason | `reason` + `detector` |
| Counters | `counters` |
| Outcome | evento `trial_outcome`, escrito **depois** de avaliar o ensaio (ainda por fazer) |

**Porque é que a deteção e a ação são eventos separados?** O enunciado pede explicitamente "enforcement actions labeled separately from detections", para se ver que a ação **se seguiu** ao alerta (e quanto tempo depois).

**Porque é que o `outcome` não é decidido pelo detetor?** O detetor só sabe que disparou. Não sabe se o ataque **atingiu o objetivo** (por exemplo, se a sessão Telnet caiu). Isso só se sabe medindo depois. Foi uma regra do `CONTEXTO-TP4`: *"o resultado final não deve ser inventado pelo detetor"*.

**Porque não registar todos os pacotes?** Num SYN flood passam milhares de pacotes por segundo. Um evento por pacote enchia o disco e afogava o Grafana. Por isso:
- a **deteção** é registada **uma vez por alerta** (campo `nova` da `Deteccao`)
- o **enforcement** é registado **no máximo 1 vez por segundo** por (detetor, origem), e o contador `pacotes_agregados` diz quantos pacotes esse evento representa
- o **volume total** (allowed vs blocked) sai no `traffic_stats` a cada 5 segundos

**O `trial_id`.** Antes de cada ensaio escreve-se o nome dele num ficheiro:
```bash
echo "T01-synflood-defesa" > ~/tp4/logs/trial_atual
```
A partir daí, todos os eventos levam essa etiqueta. Depois é fácil filtrar (`grep T01 logs/eventos.jsonl`) e, no Grafana, separar os ensaios. O enunciado pede a correlação de eventos com cada experiência.

### 6.7 `detetores/exemplo_icmp_rajada.py` — o detetor-modelo

> **Não é um ataque das aulas.** Serve só de exemplo do padrão mais usado, o **contador deslizante numa janela de tempo**, que é o que o detetor de SYN flood vai precisar.

**Regra:** se a mesma origem mandar **mais de 20** ICMP echo request (pings) em **5 segundos**, os pings a mais são descartados (`limit`). O resto passa.

**Como funciona:**

```python
self.historico = defaultdict(deque)   # para cada origem, uma fila com os instantes dos pings
self.em_alerta = set()                # origens que estão em alerta
```

Em `analisar(ctx)`, para cada pacote:
1. Se não for um ICMP echo request (tipo 8), devolve `None`.
2. Acrescenta o instante atual à fila daquela origem.
3. Tira da frente da fila os instantes com mais de 5 s (a janela "desliza").
4. Se a fila tem ≤ 20 elementos, devolve `None`, porque está dentro do limite.
5. Senão, devolve uma `Deteccao` com `acao="limit"`. O campo `nova` é `True` só se a origem ainda não estava em alerta.

Em `limpar(agora)`, cerca de 1 vez por segundo:
- tira os instantes antigos de todas as filas
- se uma origem em alerta voltou a ≤ 20, sai do alerta e é devolvida (evento `detection_clear`)
- se a fila ficou vazia, apaga a origem (a memória não cresce para sempre)

Repara que os pings **descartados também contam** para a janela. Enquanto a rajada continuar, o alerta mantém-se. É isso que se quer: medir a **taxa de tentativas**.

### 6.8 Como um colega acrescenta o seu detetor

1. Copia `detetores/exemplo_icmp_rajada.py` para, por exemplo, `detetores/syn_flood.py`.
2. Muda `nome` e `ataque` (usando o nome do ataque das aulas, por exemplo `"syn_flood"`).
3. Escreve a lógica em `analisar()` e `limpar()`.
4. Em `detetores/__init__.py`, importa a classe e acrescenta-a a `DISPONIVEIS`.
5. Em `politica.json`, acrescenta a configuração em `"detetores"` (o modo e os limites).
6. `docker-compose restart firewall`.

Não é preciso mexer no `firewall.py`, no `motor.py` nem no `eventos.py`.

---

## 7. Os testes feitos e o que provam

### Passo 1 — Rede
| Teste | Resultado | Prova |
|---|---|---|
| ping e curl cliente → servidor | ✅, `ttl=63` | O tráfego atravessa exatamente um router (a firewall) |
| `FORWARD DROP` na firewall | 100% perda | Não há bypass |

### Passo 2 — Python e falhas
| Teste | Resultado | Prova |
|---|---|---|
| ping/curl com o Python ativo | ✅ | Os pacotes passam pelo nosso código |
| `pkill` do Python | 100% perda | Fail-closed |
| 5 s depois | ✅ sozinho | Recuperação automática |

### Passo 3 — Núcleo e detetor de exemplo

**T01 — modo `enforce`** (60 pings em ~3 s):
- Resultado do ping: **20 recebidos, 66% de perda** (passam os primeiros 20, os outros 40 são limitados)
- O **HTTP continuou a funcionar** durante a rajada (o detetor não afeta outro tráfego)
- Sequência de eventos:
  ```
  10:24:13.402  detection        21 ICMP echo request em 5 s (limite 20)
  10:24:13.402  enforcement      limit (pacotes_agregados 1)
  10:24:14.444  enforcement      limit (pacotes_agregados 18)
  10:24:15.477  enforcement      limit (pacotes_agregados 18)
  10:24:16.716  traffic_stats    allow 40, limit 40
  10:24:19.936  detection_clear  (cerca de 5 s depois do último ping)
  ```
- A deteção e a ação têm o **mesmo milissegundo**: tempo de reação ≈ 0.
- `allow 40` = 20 pedidos + 20 respostas (os dois sentidos passam pela firewall).

**T02 — modo `detect_only`** (o mesmo ataque):
- Resultado do ping: **0% de perda**
- Eventos: `detection` (com `"mode": "detect_only"`) e `detection_clear`, **sem enforcement**

**T01 vs T02** é exatamente o par que o método de teste do enunciado pede: **condição não mitigada** (passo 3 do método) vs **defesa ligada** (passo 4), com o mesmo ataque e a mesma intensidade.

---

## 8. Comandos do dia a dia

### Arrancar tudo (também depois de reiniciar a VM)
```bash
cd ~/tp4
docker-compose up -d
sudo ./setup-host.sh
```

### Ver o estado
```bash
docker ps                                 # os 4 containers tp4-* em "Up"
docker logs -f tp4-firewall               # eventos em tempo real (Ctrl+C para sair)
tail -f ~/tp4/logs/eventos.jsonl          # o mesmo, a partir do ficheiro
docker exec tp4-firewall ps -ef           # processos da firewall
```

### Tráfego legítimo de teste
```bash
docker exec tp4-cliente ping -c 3 10.44.30.10
docker exec tp4-cliente curl -s -m 3 http://10.44.30.10 || echo FALHOU
```
(`-m 3` desiste ao fim de 3 s; `|| echo FALHOU` avisa quando falha, porque o `-s` esconde os erros)

### Fazer um ensaio
```bash
echo "T05-nome-do-ensaio" > ~/tp4/logs/trial_atual
# ... correr o ataque e o tráfego legítimo ...
sleep 10
grep T05 ~/tp4/logs/eventos.jsonl | cut -c1-160
```

### Mudar o modo de um detetor
```bash
sed -i 's/"modo": "enforce"/"modo": "detect_only"/' firewall/politica.json
docker-compose restart firewall
```

### Depois de mudar código da firewall
```bash
docker-compose restart firewall           # o código está montado, não precisa de build
```
Só é preciso `docker-compose build` se mudares o `Dockerfile`.

### Desligar tudo
```bash
docker-compose down
```

### Atalhos do nano
- **Ctrl+O** e **Enter**: guardar
- **Ctrl+X**: sair
- **Evitar Ctrl+Z**: suspende o nano em vez de o fechar (se acontecer: `kill -9 %1`)

---

## 9. Tabela de decisões

| # | Decisão | Alternativa rejeitada | Porquê |
|---|---|---|---|
| 1 | Python + NetfilterQueue + Scapy | C, ou uma firewall pronta | Alinhado com os TPs; é fácil de explicar; a lógica é toda nossa, como o enunciado exige |
| 2 | Containers com docker-compose na VM SEED | Só a VM, sem containers | Reprodutível com um comando; cada colega tem uma cópia igual |
| 3 | Partir do Labsetup do TP3 | TP1/TP2 | O TP3 já tinha um router entre duas redes |
| 4 | Atacante na mesma LAN do cliente (opção B) | Atacante numa rede separada (A) | Os ataques das aulas que precisam de sniffing continuam possíveis; a deteção tem de ser por comportamento |
| 5 | Redes `internal: true` | Redes normais | Sem internet nem atalhos pelo gateway do Docker; o enunciado proíbe expor o lab |
| 6 | Exceção mínima na `DOCKER-USER` (`setup-host.sh`) | Desativar `internal` ou `bridge-nf-call-iptables` | Mantém o isolamento e o bloqueio de bypass; só abre o necessário |
| 7 | Permissões mínimas por container | `cap_add: ALL` / `privileged` | O enunciado pede para limitar e documentar privilégios |
| 8 | iptables | nftables | O `nft` não vem na imagem; o iptables já foi usado nas aulas |
| 9 | Versões fixadas (`NetfilterQueue==1.1.0`, imagem SEED) | "latest" | Toda a gente obtém o mesmo resultado |
| 10 | NFQUEUE sem `--queue-bypass` (fail-closed) | Fail-open | Num lab de segurança, é preferível cortar a deixar passar sem controlo |
| 11 | `init: true` + `start.sh` com reinício em 5 s | Python como PID 1 | O PID 1 ignorava os sinais e o fail-closed não era testável; agora há recuperação automática |
| 12 | Uma só thread com `select` (acorda ≥ 1×/s) | `nfq.run()` bloqueante, ou várias threads | Alertas e estatísticas funcionam sem tráfego; sem concorrência para gerir |
| 13 | Núcleo modular + contrato `base.py` | Tudo num ficheiro | Cada colega trabalha no seu detetor sem conflitos |
| 14 | Configuração em `politica.json` | Valores no código | Mudar limites e modos sem tocar no Python; a política fica documentada num sítio |
| 15 | Modos `enforce` / `detect_only` / `off` | Comentar código para desligar | Faz o método de teste (não mitigado vs defesa) com uma linha |
| 16 | Conflitos: ganha a ação mais severa | Primeiro a disparar ganha | Regra simples, previsível e mais segura |
| 17 | Eventos JSONL; detection separado de enforcement | Texto livre num terminal | Exigido pelo enunciado; o Grafana/Loki lê JSON |
| 18 | Agregação (1 deteção por alerta, ≤1 enforcement/s, stats a cada 5 s) | Um evento por pacote | Não afoga o disco nem o dashboard num flood |
| 19 | `trial_id` via ficheiro | Sem etiqueta | Correlacionar eventos com cada ensaio |
| 20 | UTC nos eventos, monotónico nas janelas | Só a hora do sistema | Timezone exigida; as janelas não saltam se a hora mudar |
| 21 | Erro interno → drop + evento `error` | Ignorar o erro e deixar passar | Coerente com o fail-closed |
| 22 | VM com 4 GB de RAM | 2 GB | Com 2 GB a VM encravou no build; o Grafana vai precisar de mais |

---

## 10. O que ainda falta e limitações conhecidas

### Por fazer na base
- [ ] **Git** (repositório do grupo), **README** e `.gitignore`
- [ ] **`reject`**: hoje é tratado como `drop`. Deve enviar TCP RST / ICMP unreachable à origem (TODO no `firewall.py`)
- [ ] **Bloqueio no kernel**: o `block` é feito no Python. Num flood forte, cada pacote ainda vai ao Python (~3 ms cada). Pode ser preciso passar os bloqueios para o iptables (ou `ipset`) para aguentar
- [ ] **Política final**: decidir com o grupo se a omissão passa a `drop`, com uma lista de serviços permitidos
- [ ] **Teste de Telnet legítimo** através da firewall (só foi testado HTTP e ICMP)
- [ ] **Evento `trial_outcome`** e um script de ensaios (pessoa 5)
- [ ] **Grafana + Loki + Prometheus** e sondas de disponibilidade dos serviços (pessoa 5)

### Pontos em aberto da topologia
- **Como é que o atacante vai fazer sniffing?** Numa bridge Linux, o tráfego unicast entre o cliente e a firewall **não é enviado** para a porta do atacante (a bridge aprende os MACs, como um switch). Nas aulas o atacante usava `network_mode: host` e via tudo, mas isso daria-lhe acesso direto às duas redes pela VM (bypass). Há uma opção a testar: pôr a bridge `br-tp4-cli` em modo "hub" (`ageing_time 0`) para o atacante ver o tráfego sem sair do seu container. **A validar** quando começarem os ataques do TP2.
- **Atacante 2** na rede do servidor, para o sniff-and-spoof.
- **Confirmar com o professor** a hipótese do atacante na mesma LAN e o tratamento do sniffing passivo.

### Limitações (vão para a análise crítica)
- O **sniffing passivo** não é detetável em nenhuma topologia. A defesa é prevenção (bloquear Telnet e oferecer SSH).
- **Ataques que não passam pela firewall** (por exemplo, um RST forjado enviado diretamente ao cliente dentro da rede A) estão fora do alcance dela.
- **Tráfego cifrado** (SSH) não pode ser inspecionado no conteúdo.
- **Números de sequência TCP válidos não autenticam o emissor**: um atacante que vê a sessão pode forjar segmentos coerentes.
- **Latência**: ~3 ms por pacote com o Python no caminho.

---

## 11. Perguntas prováveis na oral

**"Como é que um pacote chega ao vosso código?"**
O cliente tem a firewall como rota por omissão. Na firewall, o pacote entra na cadeia FORWARD do iptables, onde uma regra o manda para a NFQUEUE 0. O nosso programa lê essa fila com o NetfilterQueue, converte o pacote com o Scapy, decide e devolve um veredito (accept ou drop) que o kernel aplica.

**"Como provam que não há caminho alternativo?"**
Pusemos a política FORWARD da firewall em DROP e o ping deixou de funcionar. Voltou ao pôr em ACCEPT. E o TTL 63 mostra exatamente um salto.

**"O que acontece se a vossa firewall cair?"**
É fail-closed: a regra NFQUEUE não tem `--queue-bypass`, por isso sem programa a ler a fila o kernel descarta os pacotes. O `start.sh` volta a lançar o Python ao fim de 5 s. Testámos com `pkill`: 100% de perda e depois recuperação automática, com a falha registada no log.

**"Porque é que o atacante está na mesma rede do cliente?"**
Porque os ataques TCP das aulas precisam que o atacante veja a sessão para obter os números de sequência. Numa rede separada esses ataques eram impossíveis, e a deteção ficava trivial (só pela interface de entrada).

**"Para que serve o setup-host.sh?"**
A VM tem `bridge-nf-call-iptables=1`, por isso o tráfego dentro das bridges passa pelo iptables da VM, onde o Docker descarta, em redes internas, os pacotes com destino fora da sub-rede. Abrimos uma exceção só para o tráfego que entra e sai pela mesma bridge. O bypass entre bridges e a saída para a internet continuam bloqueados.

**"Se dois detetores discordarem, o que acontece?"**
Ganha a ação mais severa: block > drop > reject > limit > allow.

**"Num SYN flood não enchem o disco de logs?"**
Não. A deteção é registada uma vez por alerta, a ação no máximo uma vez por segundo por origem (com o contador de pacotes agregados), e o volume vai num evento de estatísticas a cada 5 segundos.

**"Como medem a condição sem defesa?"**
Pondo o detetor em `detect_only` no `politica.json`: o ataque passa, mas a deteção fica registada. Depois repetimos com `enforce`. Os eventos de cada ensaio são separados pelo `trial_id`.

**"Porque usam dois relógios?"**
UTC com milissegundos nos eventos, para correlacionar com timezone (o enunciado exige). Monotónico nas janelas dos detetores, porque nunca salta para trás.

**"Qual é o custo de ter o Python no caminho?"**
O RTT do ping passou de ~0,15 ms para ~3 ms. Num flood, isso pode exigir mover os bloqueios para o kernel.

---

## 12. Ligação ao relatório

| Secção do relatório (enunciado, secção 8) | O que usar deste documento |
|---|---|
| Arquitetura e topologia | Secção 3 (diagrama, tabela de IPs, opção B, `internal`, permissões) |
| Packet path | Secção 5.1 |
| Failure behavior | Secções 5.3 a 5.5 |
| Software structure | Secções 6.1 a 6.4 (módulos, uma thread com `select`, arranque com `start.sh`, configuração no `politica.json`) |
| Policy model | Secções 6.4 e 6.5 (ordem de decisão, conflitos, modos) |
| Telemetry model | Secção 6.6 |
| Critical analysis | Secções 9 e 10 (decisões, limitações, latência) |
| Declaração de IA | Esta base foi desenvolvida com assistência do Claude (Anthropic). Registar a versão do modelo e como foi validada (os testes da secção 7) |

### Prints que já devem estar guardados 📸
1. O contador de DROP do Docker a subir (o diagnóstico do problema 1)
2. O ping a funcionar depois do `setup-host.sh`, com `ttl=63`
3. O teste anti-bypass (`FORWARD DROP` → 100% perda)
4. O teste de fail-closed (pkill → 100% perda → recuperação → linha do `start.sh` no log)
5. Os eventos dos ensaios T01 (enforce) e T02 (detect_only)
