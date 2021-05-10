FROM agaveplatform/grpc-go:1.14

COPY . /go/src/entrogo.com/sshpool

WORKDIR /go/src/entrogo.com/sshpool/test

RUN go mod vendor

ENTRYPOINT "/bin/bash"

CMD ["go", "test"]