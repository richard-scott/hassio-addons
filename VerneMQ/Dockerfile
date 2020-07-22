ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8
ENV VERNEMQ_VERSION=1.10.3

RUN apt-get update
RUN apt-get install --yes pwgen curl dnsutils facter nano less
RUN curl --location https://github.com/vernemq/vernemq/releases/download/$VERNEMQ_VERSION/vernemq-$VERNEMQ_VERSION.bionic.x86_64.deb --output /tmp/vernemq.deb
ENV RUNLEVEL=1
RUN apt-get install --yes /tmp/vernemq.deb
RUN rm -f /tmp/vernemq.deb

COPY limits.conf /etc/security/limits.d/vernemq.conf

HEALTHCHECK CMD vernemq ping | grep -q pong

CMD [ "/run.sh" ]
ENTRYPOINT []

COPY run.sh /
RUN chmod a+x /run.sh


