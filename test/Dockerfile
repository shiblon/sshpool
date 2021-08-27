FROM agaveplatform/grpc-go:1.14

COPY . /go/src/github.com/shiblon/sshpool

WORKDIR /go/src/github.com/shiblon/sshpool/test

RUN go mod vendor

ENTRYPOINT "/bin/bash"

CMD ["go", "test"]
