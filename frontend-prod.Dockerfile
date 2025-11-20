FROM python:3.11-slim

WORKDIR /app

# Copy frontend code
COPY Frontend /app/Frontend

# Copy Backend event generators and parsers (needed by Frontend)
COPY Backend/event_generators /app/Backend/event_generators
COPY Backend/parsers /app/Backend/parsers

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask \
    flask-cors \
    gunicorn \
    requests \
    python-dotenv

# Create entrypoint script  
RUN echo '#!/bin/bash\n\
if [ "$SERVER_MODE" = "gunicorn" ]; then\n\
    cd Frontend && exec gunicorn -w 4 -b 0.0.0.0:8000 log_generator_ui:app\n\
else\n\
    cd Frontend && exec python log_generator_ui.py\n\
fi' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 8000

CMD ["/app/start.sh"]