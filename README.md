# reverse-tunnel

Reach machines behind NAT through a bridge you run. Each host keeps one outbound connection to the bridge; SSH and
HTTP services on it become reachable at `<service>.<host>.<tunnel domain>`, with no inbound ports on the host. Under
construction: see the issues for progress.
