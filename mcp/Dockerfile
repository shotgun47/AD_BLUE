FROM python:3.11-slim

WORKDIR /app

# bloodhound-python이 LDAP/Kerberos 통신에 사용하는 시스템 라이브러리
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils \
        libsasl2-modules-gssapi-mit \
        krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ad_mcp_server.py .

# BloodHound 출력 저장 경로 (volume으로 마운트하면 호스트에서 접근 가능)
RUN mkdir -p /data/bloodhound

EXPOSE 9000

ENV MCP_TRANSPORT=http

CMD ["python", "-u", "ad_mcp_server.py"]