# 1) ئامادەکردنی zsign
FROM alpine:3.20 AS zsign
RUN apk add --no-cache git g++ make cmake openssl-dev zlib-dev linux-headers
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /zsign
WORKDIR /zsign
RUN if [ -d build/linux ]; then cd build/linux && make clean && make; \
    else cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2; fi
RUN cp "$(find /zsign -type f -name zsign -perm -u+x | head -n1)" /usr/local/bin/zsign

# 2) بۆتەکە + Telegram Local Bot API (بۆ فایلی گەورە تا 4GB)
FROM aiogram/telegram-bot-api:latest
USER root
ENTRYPOINT []
RUN apk add --no-cache python3 py3-pip openssl curl libstdc++ zlib bash
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -U aiogram cryptography
COPY --from=zsign /usr/local/bin/zsign /usr/local/bin/zsign
WORKDIR /app
COPY bot.py start.sh ./
RUN chmod +x start.sh
CMD ["./start.sh"]
