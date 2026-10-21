# ==============================================================================
# NetSentry SOC - Dockerfile Multi-stage para Portainer & Docker no Kali Linux
# ==============================================================================

# Etapa 1: Build da Aplicação React / Vite
# ATENÇÃO: É obrigatório usar Debian Bookworm Slim (glibc), pois o Vite 8 / Rolldown
# é compilado em Rust com glibc nativa e falha no Alpine (musl).
FROM node:20-bookworm-slim AS builder
WORKDIR /app

ENV NODE_OPTIONS="--max-old-space-size=2048"

# Copia dependências e instala (garante react-is exigido pelo Recharts)
COPY package*.json ./
RUN npm install react-is --save --legacy-peer-deps && npm install --legacy-peer-deps

# Copia código-fonte e compila para produção (dist/)
COPY . .
RUN npm run build

# Etapa 2: Servidor Web Nginx ultra-leve
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# Limpa arquivos padrão do Nginx
RUN rm -rf ./*

# Copia o bundle compilado da etapa anterior
COPY --from=builder /app/dist .

# Copia configuração do Nginx com proxy reverso na porta 8080
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
