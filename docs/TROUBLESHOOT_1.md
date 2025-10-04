# WireGuard 패킷 미전송 이슈

간단히 WireGuard 구성했는데, 서버에서 wireshark handshake UDP 패킷 조차 잡히지 않음
EC2 Inbound, Outbound, VPC 설정 등 모두 뒤져봤으나 정상
클라이언트 PC에서 UDP 패킷을 수동으로 전송해보았을 때, tcpdump로 확인 가능했으므로 인프라적 이슈는 아님

## 원인
PrivateKey, PublicKey를 하나로 구성해서 서버/클라이언트가 공유했었는데
WireGuard 클라이언트에 설정되어 있는 PrivateKey로 PublicKey가 생성되는 경우 Handshake를 오류나 로그 없이 안함

## 해결
서버 PrivateKey, PublicKey 클라이언트 PrivateKey, PublicKey 분리 후 문제 현상 해소됨
