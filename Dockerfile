FROM alpine:latest

ADD kube-mutating-webhook /kube-mutating-webhook
ENTRYPOINT ["./kube-mutating-webhook"]
