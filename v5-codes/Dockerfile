FROM ubuntu:18.04
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-jwt -y
RUN apt-get install python3-flask -y
RUN apt-get install vim -y
RUN apt-get install curl -y
COPY KUL-ACL /home/KUL-ACL
COPY vault /home
COPY config3.hcl /home
COPY RunUnsealVault4.sh /home
ENTRYPOINT ["home/./RunUnsealVault4.sh"]

