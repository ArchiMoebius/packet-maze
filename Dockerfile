FROM fedora:35
RUN dnf update -y && \
    dnf install -y bcc kernel-headers iproute python3-pip && \
    mkdir /opt/packet_maze/
COPY ./requirements.txt /opt/packet_maze/
COPY ./docker_entrypoint.sh /opt/packet_maze/
RUN python3 -m pip install -r /opt/packet_maze/requirements.txt && chmod +x /opt/packet_maze/docker_entrypoint.sh
WORKDIR /opt/packet_maze/
CMD ["./docker_entrypoint.sh"]
