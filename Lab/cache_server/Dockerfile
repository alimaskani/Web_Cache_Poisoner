# Use the official Nginx image
FROM nginx:alpine

# Copy the custom nginx config file to the container
COPY nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /tmp/nginx/cache /tmp/nginx/temp

# Expose port 80 for the cache server
EXPOSE 80
