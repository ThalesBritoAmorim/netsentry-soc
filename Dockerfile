# ==============================================================================
# NetSentry SOC - Dockerfile Multi-stage para Portainer & Docker no Kali Linux
# ==============================================================================

# Etapa 1: Build da Aplicação React / Vite
FROM node:20-alpine AS builder
WORKDIR /app

# Copia dependências e instala com compatibilidade para React 19
COPY package*.json ./
RUN npm install --legacy-peer-deps

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
