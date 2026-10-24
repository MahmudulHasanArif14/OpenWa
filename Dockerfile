FROM openwa/wa-automate:latest@sha256:d31f5a8f59c4890a302294e9834a25f217a973d80339896ef74cf3d35d903cb3

ENTRYPOINT []
WORKDIR /app

COPY server.js /app/server.js

CMD ["node", "/app/server.js"]
