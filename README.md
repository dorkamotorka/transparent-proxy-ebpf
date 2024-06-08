# Transparent Proxy

- Run the eBPF
```
go generate
go build
sudo ./proxy
```
  
- Run the HTTP Server from `/test` directory `go run main.go`

- Run `curl http://localhost:8000`

- Inspect eBPF logs using `sudo cat /sys/kernel/debug/tracing/trace_pipe`
