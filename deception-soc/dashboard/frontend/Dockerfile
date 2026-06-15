FROM node:18-slim AS build

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

# Production stage
FROM node:18-slim

WORKDIR /app

RUN npm install -g serve

COPY --from=build /app/dist ./dist

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "const http=require('http'); http.get('http://localhost:3000',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))" || exit 1

CMD ["serve", "-s", "dist", "-l", "3000"]
