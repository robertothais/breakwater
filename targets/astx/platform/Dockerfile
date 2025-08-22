# syntax=docker/dockerfile:1

#############################################
# 1) Base runtime (minimal shared libs)     #
#############################################
FROM --platform=amd64 debian:bookworm AS base
ENV DEBIAN_FRONTEND=noninteractive

# Minimal runtime deps (Qt is bundled in the .deb payload)
RUN apt-get update && apt-get -y upgrade && \
  apt-get -y install --no-install-recommends \
  libnetfilter-conntrack3 \
  libnfnetlink0 \
  libxml2 \
  libsqlite3-0 \
  libglib2.0-0 \
  zlib1g \
  libfontconfig1 \
  libfreetype6 \
  libstdc++6 \
  libc6 \
  tzdata socat sudo curl procps openssl

RUN dpkg --add-architecture i386 && \
  apt-get update && \
  apt-get install -y --no-install-recommends \
  libnetfilter-conntrack3:i386 \
  libnfnetlink0:i386 \
  libxml2:i386 \
  libsqlite3-0:i386 \
  libglib2.0-0:i386 \
  zlib1g:i386 \
  libfontconfig1:i386 \
  libfreetype6:i386 \
  libstdc++6:i386 \
  libc6:i386


# Copy the unpacked ASTx payload (assumes 'make unpack' has been run)
COPY unpacked/rootfs/opt/AhnLab/ASTx/ /opt/AhnLab/ASTx/

# Launcher
COPY platform/run-astx /usr/local/bin/run-astx
RUN chmod +x /usr/local/bin/run-astx

# Environment variables are now set in run-astx script for WebVM compatibility

#############################################
# 2) Dev image (analysis tools).            #
#############################################
FROM base AS dev
RUN apt-get update && apt-get -y install --no-install-recommends \
  file binutils build-essential make zsh git tmux \
  strace gdb gdbserver patchelf elfutils kmod \
  lsof iproute2 tcpdump hexyl xxd bsdmainutils netcat-openbsd \
  wget less vim python3 python3-pip python3-pycryptodome python3-cryptography

RUN apt-get install -y --no-install-recommends \
  gcc-multilib \
  libc6-dev:i386 \
  linux-libc-dev:i386

# Lulz
RUN apt-get install -y cmatrix hollywood figlet lolcat && \
  curl -L https://github.com/xero/figlet-fonts/archive/master.tar.gz | \
  tar -xz -C /tmp && \
  cp /tmp/figlet-fonts-master/*.flf /usr/share/figlet/ && \
  rm -rf /tmp/figlet-fonts-master

# Shell tools
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
RUN curl -sSfL https://raw.githubusercontent.com/ajeetdsouza/zoxide/main/install.sh | sh

# Configure shell
RUN git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions && \
  mkdir -p ~/.config && \
  sed -i 's/plugins=(git)/plugins=(git zsh-autosuggestions z docker)/' ~/.zshrc && \
  echo 'ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=#5f5f5f"' >> ~/.zshrc && \
  echo 'export PATH="/root/.local/bin:/usr/games:$PATH"' >> ~/.zshrc && \
  echo 'clear && echo' >> ~/.zshrc && \
  echo 'if [[ $$ -eq 1 || $PPID -eq 1 ]]; then clear; figlet -f Graffiti "CYBER" | lolcat; echo; fi' >> ~/.zshrc && \
  echo "set -g mouse on" >> ~/.tmux.conf

RUN chsh -s $(which zsh)

# Build library shims
WORKDIR /tmp/shims
COPY platform/shims/lib/ .
RUN make && cp *.so /usr/local/lib/

COPY platform/shims/bin/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*

WORKDIR /workspace

CMD ["zsh"]

#############################################
# 3) Runtime image                          #
#############################################
FROM base AS runtime

# Copy built library shims from dev stage (already in /usr/local/lib)
COPY --from=dev /usr/local/lib/lib*shim*.so /usr/local/lib/
COPY --from=dev /usr/local/bin/ /usr/local/bin/

RUN rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/run-astx"]

#############################################
# 4) WebVM image                            #
#############################################
FROM runtime AS webvm

# Copy WebVM IPC scripts
COPY platform/request-handler.sh /usr/local/bin/request-handler
COPY platform/start-server.sh /usr/local/bin/start-server
COPY platform/make-request.sh /usr/local/bin/make-request

# Make scripts executable
RUN chmod +x /usr/local/bin/request-handler \
  /usr/local/bin/start-server \
  /usr/local/bin/make-request

# Create directories for IPC
RUN mkdir -p /tmp/astx /var/log/astx

RUN useradd -m user && echo "user:password" | chpasswd
RUN usermod -aG sudo user
RUN echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set WebVM environment
WORKDIR /home/user/
ENV HOME="/home/user" TERM="xterm" USER="user" SHELL="/bin/bash"

USER root
RUN echo 'root:password' | chpasswd

# Use standard bash entrypoint for WebVM
CMD ["/bin/sh"]
