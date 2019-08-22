# ossec-metrics

A very simple app which polls `/var/ossec/bin/agent_control` and reports the number of active agents and total agents as the prometheus metrics `ossec_metrics_active_agents` and `ossec_metrics_total_agents`

Sorry there isn't a makefile, to build:

```shell
go build -o ossec-metrics cmd/ossec-metrics/main.go
```

To cross compile for a Raspberry Pi

```shell
GOOS=linux GOARCH=arm GOARM=7 go build -o ossec-metrics-linux-armv7 cmd/ossec-metrics/main.go
```
