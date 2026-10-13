

#     docker run --rm -p 8080:8080 -e MISTRAL_API_KEY knox-rt
#

#     docker run --rm -v "$PWD:/work" -w /work -e MISTRAL_API_KEY \
#         knox-rt knox-rt -c config.yaml \
#         -t openai --target-name gpt-4o-mini --target-api-key "$OPENAI_API_KEY" \
#         --plugins prompt-injection -n 5 -o results.json

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app


COPY pyproject.toml README.md ./
RUN mkdir -p plugins detectors strategies inference ui/backend/static \
 && touch cli.py run.py config.py \
 && pip install ".[all,ui]" \
 && pip uninstall -y knox-rt \
 && rm -rf plugins detectors strategies inference ui cli.py run.py config.py build *.egg-info

COPY . .


RUN pip install --no-deps -e . \
 && useradd --create-home --uid 1000 knox \
 && chown -R knox:knox /app

USER knox

EXPOSE 8080

CMD ["knox-rt-ui"]
