FROM ghcr.io/sandbox-quantum/switch-core:latest

WORKDIR /workspace

# Copy application files into the container
COPY . /workspace

# Ensure scripts are executable
RUN chmod +x /workspace/start.sh

# Default port for Render web service
EXPOSE 10000

CMD ["/workspace/start.sh"]
