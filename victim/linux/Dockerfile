# Deliberately vulnerable Ubuntu victim (lab-isolated).
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ARG STACK_VERSION=8.14.3
ENV STACK_VERSION=${STACK_VERSION}

RUN apt-get update && apt-get install -y \
      openssh-server sudo curl wget python3 cron auditd rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Elastic Agent is baked into the image rather than downloaded at enroll time:
# enrollment then needs no internet, and a rebuild can't be broken by a moved
# artifact URL. Extracted, NOT installed - `elastic-agent install` wants systemd,
# which a container doesn't have. See enroll.sh.
# --retry: this pulls ~500 MB, and a single transient blip from artifacts.elastic.co
# (seen in practice as "curl: (92) HTTP/2 stream 0 was not closed cleanly") aborts
# the whole install with a cryptic error before the lab ever starts. Retry instead,
# and force HTTP/1.1 because the failure mode is specific to HTTP/2 multiplexing.
RUN curl -fsSL --http1.1 --retry 5 --retry-delay 5 --retry-all-errors --connect-timeout 30 \
      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${STACK_VERSION}-linux-x86_64.tar.gz" \
      -o /tmp/agent.tgz \
 && mkdir -p /opt/elastic-agent \
 && tar xzf /tmp/agent.tgz -C /opt/elastic-agent --strip-components=1 \
 && rm -f /tmp/agent.tgz

ARG VICTIM_USER=jdoe
ARG VICTIM_PASS=Password123

COPY enroll.sh     /opt/enroll.sh
COPY weaken.sh     /opt/weaken.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/enroll.sh /opt/weaken.sh /opt/entrypoint.sh \
 && VICTIM_USER="$VICTIM_USER" VICTIM_PASS="$VICTIM_PASS" /opt/weaken.sh
EXPOSE 22
CMD ["/opt/entrypoint.sh"]
