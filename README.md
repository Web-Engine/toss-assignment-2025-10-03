# Toss

## Environment
```
AWS EC2 Ubuntu 24.04 x86_64 6.14.0-1011-aws
```

## Install mise
```shell
curl https://mise.run | sh
echo "eval \"\$(/home/ubuntu/.local/bin/mise activate bash)\"" >> ~/.bashrc
source ~/.bashrc
```

## Install go
```shell
wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' > ~/.bashrc
source ~/.bashrc
```

#### 수동 설정
```shell
# TODO: 줄일 수 있는게 있으면 줄여봅시다.
sudo apt update
sudo apt install -y \
  wireguard \
  resolvconf \
  libnetfilter-queue-dev \
  libnfnetlink-dev \
  build-essential \
  pkg-config \
  libmnl-dev
```
