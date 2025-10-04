# Network Software Engineer 과제
- Author : 조태상(gsts007@gmail.com)

## 프로젝트 빌드 및 실행 방법

### 프로젝트 기반 환경
```
AWS EC2 Ubuntu 24.04 x86_64 6.14.0-1011-aws
```

### 프로젝트 의존성 설치
```shell
# install go
wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' > ~/.bashrc
source ~/.bashrc

# install deps
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

### 빌드
```shell
go build -o ./build/toss
```

### 실행
```shell
# wireguard 실행
sudo wg-quick up ./wireguard/wg0.conf

# tproxy application 실행
sudo ./build/toss
```

## 주요 기능 및 구현 방식

### 1. VPN 트래픽 수신
WireGuard VPN에서 전송되는 트래픽을 수신합니다.

WireGuard로 wg0 인터페이스를 생성하고, wg0 인터페이스로 들어오는 패킷들을 TPROXY를 사용하여 가로채 처리합니다.
TPROXY application에서 원래 목적지와 연결하여 패킷을 처리합니다.

또한, 사설 IP 대역(10.0.0.0/24)에서 목적지로 나가는 패킷을 MASQUERADE하여 공인 IP로 변환하여 통신하도록 합니다. 

### 2. 트래픽 필터링
TCP 포트와 관계 없이 HTTP/1.1, HTTP/2(h2) 프로토콜을 식별하여 패킷을 처리합니다.  
이 외의 프로토콜은 그대로 송수신하여 정상 동작합니다.

 - HTTP/1.1 프로토콜은 처음 전송되는 HTTP Method(`GET`, `POST`, `DELETE` 등)를 인식합니다. (http11_detector.go)   
 - HTTP/2(h2) 프로토콜은 처음 전송되는 `PRI * HTTP/2.0` 를 인식합니다. (`http2_detector.go`)  
 - TLS 프로토콜은 처음 전송되는 `ClientHello` 메세지를 인식합니다. (`tls_detector.go`)
 - TCP 스트림 데이터가 일정량(128 B) 이상이 되었음에도 감지에 실패하는 경우 모르는 프로토콜로 간주하고 그대로 송수신합니다. (`detect_handler.go`)

### 3. HTTP/HTTPS MITM 프록시
HTTP/HTTPS 트래픽에서 대해서 self-signed CA 인증서를 기반으로 TLS 위변조를 수행합니다.

#### TLS (`tls_handler.go`)
- 클라이언트가 요청한 ClientHello 정보를 기반으로, 목적 서버에 TLS handshake를 수행합니다.
- 목적 서버의 TLS handshake가 성공하면, 클라이언트가 요청한 ServerName으로 self-signed CA 기반 TLS 인증서를 생성하고 handshake 합니다.
- 이 때, 클라이언트, 서버의 SNI, ALPN 정보를 유지하고, ALPN에 따라 HTTP/1.1, HTTP/2(h2)로 분기하여 처리하였습니다.
- TLS handshake에는 `crypto` 라이브러리를 활용하였습니다.

#### HTTP/1.1 (`http11_handler.go`)
- HTTP/1.1 프로토콜은 단일 요청/단일 응답이 반복되는 단순한 구조로 `net/http` 라이브러리를 통해 HTTP request, response를 파싱했습니다.
- HTTP/1.1에서 WebSocket으로 업그레이드 되는 경우, 단일 요청/단일 응답 구조가 깨지므로 별도로 처리합니다.

#### HTTP/2 (`http2_handler.go`)
- h2 프로토콜은 http2 frame을 통해 다양한 요청/응답이 양방향으로 오갈 수 있기 때문에, HTTP/1.1 처럼 단순한 구현이 어렵습니다.
- `golang.org/x/net/http2` 라이브러리를 활용하여, Downstream TCP Connection을 처리하는 HTTP2 서버를 생성하고 들어오는 요청들을 Upstream TCP Connection에 h2 프로토콜로 전송하였습니다.

### 4. 로깅
Application에서 발생하는 다양한 로그를 기록합니다.
또한, HTTP/HTTPS 트래픽의 request, response 내용을 상세히 기록합니다.

- `slog`를 활용하여 구조화 된 로그 시스템을 설정하였습니다.
- 동일한 tcp stream을 추적할 수 있도록 tunnel id, src addr, dst addr를 기록했습니다.

- http1.1, h2의 요청 method, host, url, body / 응답 status, status code, headers, body를 기록하였습니다.
- 이 때, 요청 및 응답 body는 양이 많을 수 있으므로 128B로 자르고 string으로 변환했습니다.

### 5. 특정 호스트 HTTPS MITM 공격 제외
`toss.im`, `www.example.com`에 대한 MITM 공격을 제외합니다.

TLS 감지 구현체(`tls_detector.go`)에서

### 6. 프로토콜 HTTP/3 기반 MITM 프록시
미구현

## 각 기능별 테스트 방법 및 결과

## 고려했던 문제점 및 해결 방안

## 개선 및 확장 방안

