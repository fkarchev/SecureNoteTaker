# SECURITY: Multi-stage build
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Serve with Nginx
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# SECURITY: By default, the official nginx alpine image runs worker processes as the 'nginx' user,
# which drops privileges after binding to port 80 as root.

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
