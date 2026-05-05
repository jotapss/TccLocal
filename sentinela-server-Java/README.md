# 🛡️ Sentinela DevSecOps — Servidor Java

> **Responsável:** Isadora Lyra
> **Linguagem:** Java 17 + Spring Boot 3.2.5
> **Projeto:** Sentinela DevSecOps — Camada Servidor / API Central

---

## 📋 Índice

1. [O que é o Sentinela?](#1-o-que-é-o-sentinela)
2. [O que cabe à Isadora Lyra](#2-o-que-cabe-à-isadora-lyra)
3. [Arquitetura geral do projeto](#3-arquitetura-geral-do-projeto)
4. [Estrutura de pacotes do servidor](#4-estrutura-de-pacotes-do-servidor)
5. [Como rodar localmente com Docker](#5-como-rodar-localmente-com-docker)
6. [Como rodar os testes automatizados](#6-como-rodar-os-testes-automatizados)
7. [Variáveis de ambiente](#7-variáveis-de-ambiente)
8. [Endpoints da API](#8-endpoints-da-api)
9. [Pipeline de segurança](#9-pipeline-de-segurança)
10. [Padrões de projeto implementados](#10-padrões-de-projeto-implementados)
11. [Decisões técnicas e justificativas](#11-decisões-técnicas-e-justificativas)
12. [Requisitos atendidos](#12-requisitos-atendidos)
13. [Limitações e trabalhos futuros](#13-limitações-e-trabalhos-futuros)
14. [Divisão de responsabilidades do time](#14-divisão-de-responsabilidades-do-time)
15. [Dependências](#15-dependências)

---

## 1. O que é o Sentinela?

O **Sentinela** é uma plataforma DevSecOps acadêmica (TCC) que detecta credenciais expostas — como chaves AWS, tokens GitHub e senhas em arquivos `.env` — em tempo real nos ambientes de desenvolvimento. Quando um desenvolvedor salva um arquivo com uma credencial, o agente detecta em menos de 500ms e um alerta aparece no dashboard.

O sistema é composto por **4 camadas** desenvolvidas por membros distintos do time:

| Camada | Tecnologia | Responsável |
|---|---|---|
| 🟢 **Agente** | Node.js 18 LTS | Gustavo Martins |
| 🔵 **Servidor/API** | Java 17 + Spring Boot 3 | **Isadora Lyra** |
| 🟣 **Frontend** | React + Vite | João Paulo |
| 🟡 **Infraestrutura Docker** | Docker Compose | Gustavo Martins |

---

## 2. O que cabe à Isadora Lyra

Esta camada é responsável por **receber, validar, decifrar e persistir** os alertas enviados pelo agente Node.js, além de expor a API REST consumida pelo dashboard React.

| Componente | Descrição |
|---|---|
| **API REST** | Endpoints de autenticação, alertas, agentes e dashboard |
| **Segurança** | JWT, X-Agent-Token, RSA-4096, HMAC-SHA256, Rate Limiting |
| **Pipeline de alertas** | Chain of Responsibility → Strategy → Factory |
| **Persistência** | PostgreSQL via JPA/Flyway com Audit Log imutável |
| **Infraestrutura** | Docker Compose com rede isolada para o banco |

---

## 3. Arquitetura geral do projeto

```
Sistemas Monitorados (arquivos do desenvolvedor)
        │
        │  Chokidar FS Watch (< 500ms)
        ▼
┌─────────────────────────────────────────────────────┐
│         🟢 AGENTE Node.js 18 (Gustavo Martins)      │
│  Scanner → Masking → Cifra RSA-4096 → HMAC-SHA256  │
└─────────────────────────────────────────────────────┘
        │  POST /api/v1/alerts  │  X-Agent-Token  │  JWT
        ▼
┌─────────────────────────────────────────────────────┐
│     🔵 SERVIDOR Java 17 + Spring Boot (Isadora)     │
│                                                     │
│  JwtAuthFilter → AgentAuthFilter → RateLimiting     │
│       ↓                                             │
│  HMAC Validation → RSA Decrypt                      │
│       ↓                                             │
│  Chain of Responsibility (Validation → Sanitization │
│  → Deduplication)                                   │
│       ↓                                             │
│  Strategy (Critical / Medium / Low)                 │
│       ↓                                             │
│  Factory → Persist (mascarado) → Audit Log          │
└─────────────────────────────────────────────────────┘
        │  JPA + Prepared Statements
        ▼
┌──────────────────────────────┐
│  🗄️ PostgreSQL (Rede Isolada) │
│  internal: true no Docker    │
└──────────────────────────────┘
        │  REST API + JWT
        ▼
┌──────────────────────────────┐
│  🟣 React + Vite (João Paulo) │
└──────────────────────────────┘
```

---

## 4. Estrutura de pacotes do servidor

```
br.edu.sentinela/
├── config/
│   ├── CryptoConfig.java          # Singleton RSA-4096 (@Bean PrivateKey + PublicKey)
│   ├── SecurityConfig.java        # Spring Security, filtros, roles, CORS, STATELESS
│   ├── CorsConfig.java            # CORS com origens via variável de ambiente
│   └── DataInitializer.java       # Cria usuário admin automaticamente na 1ª execução
├── controller/
│   ├── AuthController.java        # POST /auth/token, /auth/refresh, /auth/login
│   ├── AlertController.java       # POST/GET/PUT /alerts
│   ├── AgentController.java       # POST /agents/register, GET /agents/{id}/status
│   └── DashboardController.java   # GET /dashboard/summary, /dashboard/timeline
├── dto/
│   ├── request/                   # AlertEnvelopeRequest, AgentRegisterRequest, etc.
│   └── response/                  # AlertResponse, AgentRegisterResponse, PagedResponse, etc.
├── exception/
│   ├── GlobalExceptionHandler.java
│   └── (DecryptionException, HmacValidationException, RateLimitException, etc.)
├── filter/
│   ├── JwtAuthFilter.java         # Valida JWT — OncePerRequestFilter
│   ├── AgentAuthFilter.java       # Valida X-Agent-Token via hash SHA-256
│   └── RateLimitingFilter.java    # Bucket4j — 100 req/min por agente
├── model/
│   ├── Alert.java, Agent.java, User.java
│   ├── AuditLog.java              # @Immutable — nunca pode ser deletado
│   └── enums/                     # Severity, AlertStatus, Environment, UserRole
├── repository/
│   ├── AlertRepository.java, AgentRepository.java, UserRepository.java
│   └── AuditLogRepository.java    # Estende Repository (sem delete)
├── security/
│   ├── JwtService.java            # Gera/valida JWT com claims type e token_type
│   ├── RsaDecryptionService.java  # RSA/ECB/OAEPWithSHA-256AndMGF1Padding
│   ├── HmacValidationService.java # MessageDigest.isEqual() — timing-safe
│   └── DataMaskingService.java    # Mascara AWS/GitHub/genérico antes de persistir
└── service/
    ├── chain/                     # Chain of Responsibility
    │   ├── ValidationHandler.java     # Valida campos, severity, event_time ±30s
    │   ├── SanitizationHandler.java   # Sanitiza entradas
    │   └── DeduplicationHandler.java  # SHA-256 checksum para idempotência
    ├── factory/AlertFactory.java      # Cria objetos Alert a partir do payload
    ├── strategy/                      # Strategy Pattern por severidade
    │   ├── CriticalAlertStrategy.java
    │   ├── MediumAlertStrategy.java
    │   └── LowAlertStrategy.java
    ├── impl/AlertServiceImpl.java     # Orquestra o pipeline completo
    ├── AgentService.java
    ├── AuditLogService.java
    └── DashboardService.java
```

**Recursos:**
```
src/main/resources/
├── application.properties         # Todas as configurações do servidor
├── application-test.properties    # H2 em memória para testes (sem Flyway)
├── logback-spring.xml             # Mascara Bearer, AKIA, ghp_, PEM nos logs
├── keys/                          # Arquivos PEM gerados localmente (nunca versionados)
└── db/migration/V1__create_tables.sql  # 4 tabelas + índices + pgcrypto
```

---

## 5. Como rodar localmente com Docker

### Pré-requisitos

- Docker Desktop instalado e **aberto** (ícone da baleia estático na barra de tarefas)
- Git

### Configuração inicial (apenas na primeira vez)

**1. Clone o repositório:**
```bash
git clone https://github.com/<seu-usuario>/sentinela-server-Java.git
cd sentinela-server-Java
```

**2. Gere as chaves RSA-4096** (requer OpenSSL — disponível no Git Bash):
```bash
openssl genrsa -out pk_raw.pem 4096
openssl pkcs8 -topk8 -nocrypt -in pk_raw.pem -out src/main/resources/keys/private_key.pem
openssl rsa -in pk_raw.pem -pubout -out src/main/resources/keys/public_key.pem
rm pk_raw.pem
```

> ⚠️ Envie o arquivo `public_key.pem` ao responsável pelo agente Node.js por canal privado. Nunca suba as chaves para o GitHub.

**3. Crie o arquivo `.env`:**
```bash
cp .env.example .env
```

Preencha o `.env` com os valores reais. Para gerar o `JWT_SECRET`:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
```

O `HMAC_SECRET` deve ser **idêntico** ao configurado no agente Node.js — combinar por canal privado com o Gustavo.

**4. Suba o sistema:**
```bash
docker-compose up --build -d
```

**5. Verifique se subiu:**
```bash
curl http://localhost:8080/actuator/health
# Esperado: {"status":"UP"}
```

### Comandos úteis

```bash
# Ver logs do servidor em tempo real
docker-compose logs -f sentinela-server

# Parar tudo
docker-compose down

# Parar e apagar os dados do banco
docker-compose down -v

# Reconstruir após mudanças no código
docker-compose up --build -d
```

---

## 6. Como rodar os testes automatizados

O projeto possui **34 testes automatizados** que rodam com banco H2 em memória — sem necessidade de Docker.

```bash
mvn test -Dspring.profiles.active=test
```

**Resultado esperado:**
```
Tests run: 34, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### O que os testes cobrem

| Classe de Teste | O que verifica |
|---|---|
| `RsaDecryptionServiceTest` | Cifragem e decifragem RSA-4096 com OAEP+SHA256 |
| `HmacValidationServiceTest` | Validação HMAC-SHA256 com comparação timing-safe |
| `AlertServiceImplTest` | Pipeline completa: validação → sanitização → deduplicação → persistência |
| `RateLimitingFilterTest` | Bloqueia na 101ª requisição, retorna 429 + Retry-After |
| `AlertControllerIntegrationTest` | Endpoints REST completos com banco H2 |
| `JwtServiceTest` | Geração, validação e expiração de tokens JWT |

---

## 7. Variáveis de ambiente

Copie `.env.example` para `.env` e preencha:

| Variável | Obrigatório | Descrição |
|---|---|---|
| `DB_PASSWORD` | ✅ | Senha do usuário PostgreSQL |
| `JWT_SECRET` | ✅ | Secret para assinar tokens JWT (base64, 64 bytes) |
| `HMAC_SECRET` | ✅ | Segredo compartilhado com o agente Node.js (hex, 64 bytes) |
| `JASYPT_ENCRYPTOR_PASSWORD` | ✅ | Senha mestre do Jasypt para propriedades encriptadas |
| `ADMIN_PASSWORD` | ✅ | Senha do usuário admin criado pelo DataInitializer |
| `RATE_LIMIT_PER_MINUTE` | — | Requisições por minuto por agente (padrão: 100) |
| `CORS_ALLOWED_ORIGINS` | — | Origens permitidas para CORS (padrão: localhost:3000) |

> ❌ **Nunca versione o arquivo `.env`** — ele está no `.gitignore`.
> ❌ **Nunca versione os arquivos `.pem`** das chaves RSA — também no `.gitignore`.

---

## 8. Endpoints da API

Todos os endpoints são prefixados com `/api/v1`.

### Autenticação

| Método | Endpoint | Descrição | Auth |
|---|---|---|---|
| POST | `/auth/login` | Login do usuário — retorna JWT via cookie | Pública |
| POST | `/auth/token` | Obtém token JWT para agente | X-Agent-Token |
| POST | `/auth/refresh` | Renova token JWT expirado | JWT |

### Alertas

| Método | Endpoint | Descrição | Auth |
|---|---|---|---|
| POST | `/alerts` | Recebe alerta cifrado do agente | JWT + X-Agent-Token |
| GET | `/alerts` | Lista alertas com paginação e filtros | JWT |
| PUT | `/alerts/{id}` | Atualiza status do alerta (ex: RESOLVED) | JWT |

### Agentes

| Método | Endpoint | Descrição | Auth |
|---|---|---|---|
| POST | `/agents/register` | Registra novo agente — retorna agentToken e publicKey | JWT (admin) |
| GET | `/agents/{id}/status` | Health e métricas do agente | JWT |

### Dashboard

| Método | Endpoint | Descrição | Auth |
|---|---|---|---|
| GET | `/dashboard/summary` | Resumo: totais, agentes online, top rules | JWT |
| GET | `/dashboard/timeline` | Retorna resumo de alertas das últimas 24h (mesmos dados do summary nesta versão) | JWT |

### Envelope esperado no POST /alerts

```json
{
  "data":       "<payload JSON cifrado com RSA-4096, Base64>",
  "signature":  "<HMAC-SHA256 do payload original, hex>",
  "checksum":   "<SHA-256 do payload original, hex>",
  "agent_id":   "agent-prod-01",
  "severity":   "CRITICAL",
  "event_time": "2025-01-15T10:30:00.123Z",
  "rule_id":    "AWS_ACCESS_KEY_001",
  "file_path":  "/app/config/.env"
}
```

### Códigos de resposta

| Código | Significado |
|---|---|
| 200 | Sucesso / Alerta duplicado (idempotente) |
| 201 | Alerta criado / Agente registrado |
| 400 | Payload inválido ou event_time fora de ±30s |
| 401 | JWT ausente/expirado ou X-Agent-Token inválido |
| 403 | Autenticado mas sem permissão |
| 409 | Conflito — checksum duplicado |
| 429 | Rate limit excedido — respeitar header Retry-After |
| 500 | Erro interno — agente deve ativar buffer com backoff |

---

## 9. Pipeline de segurança

Cada alerta percorre exatamente 12 passos:

```
 1. [Agente]   Regex detecta credencial
 2. [Agente]   Data Masking (AKIA → AKIA*****LE)
 3. [Agente]   Cifra RSA-4096 com chave pública do servidor
 4. [Agente]   Assina HMAC-SHA256 do payload original
 5. [Agente]   POST /api/v1/alerts com JWT + X-Agent-Token
 6. [Servidor] JwtAuthFilter valida JWT
 7. [Servidor] AgentAuthFilter valida X-Agent-Token (hash SHA-256)
 8. [Servidor] RateLimitingFilter — Bucket4j 100 req/min
 9. [Servidor] HmacValidationService — timing-safe
10. [Servidor] RsaDecryptionService — decifra com chave privada
11. [Servidor] Chain of Responsibility (Validation → Sanitization → Deduplication)
12. [Servidor] Strategy por severidade → Factory → Persiste mascarado → AuditLog
```

---

## 10. Padrões de projeto implementados

Todos os padrões foram implementados como requisito acadêmico do TCC:

| Padrão | Onde | Descrição |
|---|---|---|
| **Singleton** | `CryptoConfig.java` | Par de chaves RSA-4096 instanciado uma vez via `@Bean` |
| **Chain of Responsibility** | `service/chain/` | `ValidationHandler → SanitizationHandler → DeduplicationHandler` |
| **Strategy** | `service/strategy/` | `CriticalAlertStrategy`, `MediumAlertStrategy`, `LowAlertStrategy` |
| **Factory** | `service/factory/AlertFactory.java` | Cria objetos `Alert` a partir do payload decifrado |

---

## 11. Decisões técnicas e justificativas

### RSA-4096 com OAEP+SHA256
O padrão PKCS#1 v1.5 é vulnerável ao **ataque de Bleichenbacher** desde 1998. O modo OAEP elimina essa vulnerabilidade ao adicionar aleatoriedade ao processo de cifragem. Usamos SHA-256 internamente porque MD5 e SHA-1 foram matematicamente quebrados.

### HMAC com `MessageDigest.isEqual()`
Comparações de strings convencionais criam **timing attacks** — um invasor mede microssegundos de diferença no tempo de resposta para descobrir o segredo byte a byte. O `MessageDigest.isEqual()` compara todos os bytes em tempo constante, eliminando esse vazamento de informação.

### Mascaramento antes de qualquer envio (Zero Knowledge)
O servidor não precisa conhecer o segredo real para emitir um alerta útil. Armazenar o valor real criaria um segundo ponto de falha — o banco do Sentinela se tornaria alvo de ataques.

### PostgreSQL em rede `internal: true`
**Defense in depth**: o banco não possui nenhuma rota de rede para o exterior. Um invasor precisaria comprometer dois containers separados para acessar os dados.

### Audit Log imutável com `@Immutable`
**Non-repudiation**: em incidentes de segurança, a primeira ação de um invasor é apagar rastros. A anotação `@Immutable` do Hibernate impede UPDATE e DELETE na tabela de auditoria em nível de ORM.

### JWT com expiração de 15 minutos
Tokens de longa duração são vetores de ataque comuns. Com 15 minutos, a janela de exploração em caso de interceptação é mínima.

### Validação de `event_time` com tolerância de ±30 segundos
Previne **replay attacks** — um invasor não consegue reutilizar um envelope interceptado depois de 30 segundos, pois o servidor rejeita alertas com timestamp muito antigo ou futuro.

---

## 12. Requisitos atendidos

### Funcionais

| RF | Descrição | Implementado em |
|---|---|---|
| RF01 | Detectar credenciais expostas | Agente Node.js (Gustavo) |
| RF02 | Classificar riscos por severidade | `Severity.java` + `AlertStrategy` |
| RF03 | Persistir alertas com mascaramento | `AlertServiceImpl` + `DataMaskingService` |
| RF04 | Autenticar agentes com token único | `AgentAuthFilter` + `AgentService` |
| RF05 | Deduplicar alertas por checksum | `DeduplicationHandler` |
| RF06 | Expor dashboard com métricas | `DashboardController` + `DashboardService` |
| RF07 | Registrar agentes e retornar publicKey | `AgentController` + `AgentService` |
| RF08 | Histórico de alertas com paginação | `AlertController` (GET com filtros) |
| RF09 | Autenticação JWT para o frontend | `AuthController` + `JwtService` |

### Não-Funcionais

| RNF | Descrição | Como atendido |
|---|---|---|
| RNF01 | Latência < 500ms | Pipeline otimizada, sem I/O desnecessário |
| RNF02 | Falso positivo < 2% | Regras regex precisas no agente |
| RNF03 | Criptografia RSA-4096 | `RsaDecryptionService` com OAEP+SHA256 |
| RNF04 | Autenticação de agente | `AgentAuthFilter` com X-Agent-Token |
| RNF05 | Mascaramento duplo | `DataMaskingService` + masking no agente |
| RNF06 | Rate limiting | `RateLimitingFilter` com Bucket4j |
| RNF07 | Containerização Docker | `docker-compose.yml` com redes isoladas |
| RNF08 | HMAC-SHA256 timing-safe | `HmacValidationService` |
| RNF09 | Banco em rede isolada | `internal: true` no Docker Compose |
| RNF10 | Graceful shutdown | Agente Node.js (SIGTERM/SIGINT) |
| RNF11 | Audit Log imutável | `AuditLog.java` com `@Immutable` |
| RNF12 | Logs sem vazamento de segredos | `logback-spring.xml` com redação automática |

---

## 13. Limitações e trabalhos futuros

Para honestidade acadêmica, estas funcionalidades existem em produção real mas estão fora do escopo do TCC:

| Funcionalidade | Descrição |
|---|---|
| **Certificado SSL/TLS** | O sistema usa HTTP local. Em produção, HTTPS via Let's Encrypt |
| **Rotação automática de chaves** | As chaves RSA são permanentes. Em produção, rotação a cada 90 dias via AWS KMS |
| **Autenticação multifator (MFA)** | O login usa usuário e senha. MFA com TOTP seria a próxima camada |
| **WAF** | Em produção, Cloudflare ou similar bloquearia tráfego malicioso automaticamente |
| **Plugin publicado no VS Code** | O agente funciona como processo standalone. Publicação na marketplace é o próximo passo |

---

## 14. Divisão de responsabilidades do time

| Membro | Camada | Tecnologia | Responsabilidades |
|---|---|---|---|
| **Gustavo Martins** | Agente + Docker | Node.js 18 | Scanner, crypto, masking, buffer, transporte, Dockerfile, docker-compose |
| **Isadora Lyra** | Servidor | Java 17 + Spring Boot 3 | API REST, Chain of Responsibility, Strategy, Factory, HMAC, RSA decrypt, Audit Log |
| **João Paulo** | Frontend | React + Vite | Dashboard, gráficos, autenticação JWT, CSP |
| **Caio & André** | Regras | (integradas no agente) | Padrões regex de detecção |

---

## 15. Dependências

| Dependência | Versão | Uso |
|---|---|---|
| `spring-boot-starter-web` | 3.2.5 | API REST com Tomcat embarcado |
| `spring-boot-starter-security` | 3.2.5 | Filtros de autenticação e autorização |
| `spring-boot-starter-data-jpa` | 3.2.5 | Persistência com Hibernate |
| `spring-boot-starter-validation` | 3.2.5 | Validação de DTOs com Bean Validation |
| `spring-boot-starter-actuator` | 3.2.5 | Health check em `/actuator/health` |
| `postgresql` | 42.6.2 | Driver do banco de dados |
| `flyway-core` | 9.22.3 | Migrations do banco de dados |
| `jjwt-api` | 0.12.5 | Geração e validação de tokens JWT |
| `bucket4j-core` | 8.7.0 | Rate limiting com algoritmo Token Bucket |
| `jasypt-spring-boot-starter` | 3.0.5 | Encriptação de propriedades sensíveis |
| `lombok` | 1.18.32 | Redução de boilerplate (getters, builders, etc.) |
| `h2` | (test) | Banco em memória para testes automatizados |

---

## ❌ Regras importantes

- **Nunca versionar o `.env`** — contém senhas reais
- **Nunca versionar os arquivos `.pem`** — contêm as chaves RSA
- **Nunca hardcodar senhas no código** — sempre via variáveis de ambiente
- **Nunca compartilhar o `HMAC_SECRET` pelo GitHub** — apenas por canal privado com o Gustavo

---

*Sentinela DevSecOps — Servidor Java · Java 17 + Spring Boot 3.2.5 + PostgreSQL + Docker · TCC ADS*
