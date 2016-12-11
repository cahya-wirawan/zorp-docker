FROM ubuntu:14.04

MAINTAINER Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

RUN apt-key adv --keyserver hkp://keyserver.opensuse.org:80 --recv-keys 0x69d1b2aaee3d166a
 && echo "deb http://download.opensuse.org/repositories/security:/Zorp:/6:/0:/10/xUbuntu_14.04/ ./" >/etc/apt/sources.list.d/zorp.list \
 && apt-get update
RUN touch -c /etc/zorp/dh.pem \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    zorp \
    zorp-modules \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/tmp/* \
 && rm -rf /tmp/* \
 && touch /etc/zorp/dh.pem

ENV ZORP_CONFIG_DIR /etc/zorp/
ADD policy.py $ZORP_CONFIG_DIR/policy.py

COPY . /app/

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD [ \
     "/usr/lib/zorp/zorp", \
     "--foreground", \
     "--no-syslog", \
     "--user", "zorp", \
     "--group", "zorp", \
     "--verbose", "3", \
     "--log-spec", "*.accounting:4,core.summary:4", \
     "--as", "default" \
    ]
