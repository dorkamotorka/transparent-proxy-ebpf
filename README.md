# Transparent Proxy

A transparent proxy, also known as an inline proxy, intercepts client requests and redirects them without modifying the request or requiring client-side configuration. It operates invisibly to users, meaning they are unaware of its presence and do not need to adjust their network settings. This technology is invaluable for network management, security policy enforcement, traffic monitoring, and optimization. Transparent proxies can execute a range of functions, including content filtering, cache acceleration, traffic control, and load balancing. Commonly used technologies for implementing transparent proxies include TPROXY, NAT, and others.

In this repository, I implementated Transparent proxy using eBPF. Specifically, I utilize Golang alongside the ebpf-go package.

## How to Run

https://github.com/user-attachments/assets/325745b2-9be1-43cd-bd64-14fa6ac5f5e0

First build and run the eBPF program:
```
go generate
go build
sudo ./proxy
```

Now let's verify it works as expected:

- Run the HTTP Server from `/test` directory `go run main.go`

- From another shell, run `curl http://localhost:8000`

You can then inspect eBPF logs using `sudo cat /sys/kernel/debug/tracing/trace_pipe` to verify transparent proxy indeed intercepts the network traffic.
