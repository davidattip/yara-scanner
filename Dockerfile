# Image de production — YARA Static Code Analyzer (interface web).
# Base Linux : quelle que soit la machine hôte (Windows, Mac, Linux), le
# conteneur tourne de façon identique — c'est ce qui neutralise les
# différences de déploiement entre systèmes d'exploitation.

FROM python:3.12-slim

# Sortie non bufferisée (logs immédiats) et pas de .pyc dans l'image.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 1. Dépendances Python d'abord (meilleure mise en cache des couches Docker).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 2. Module ML optionnel (bonus). Passer --build-arg WITH_ML=false pour une
#    image plus légère ; l'app dégrade proprement sans scikit-learn.
ARG WITH_ML=true
RUN if [ "$WITH_ML" = "true" ]; then \
        pip install --no-cache-dir scikit-learn joblib ; \
    fi

# 3. Code de l'application (le modèle ML entraîné est inclus dans models/).
COPY . .

EXPOSE 5000

# Serveur WSGI de production. Un seul worker multi-thread : l'aperçu du
# dernier scan (pour l'export de rapport) est gardé en mémoire de processus,
# on évite ainsi qu'un worker différent le perde.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "1", "--threads", "4", "--timeout", "120", \
     "wsgi:app"]
