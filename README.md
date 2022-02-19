# 環境構築

```
# Debian
$ apt-get update
$ apt-get install pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl
$ pip install xmlsec
$ pip install isodate
$ pip install python3-saml
```

## Docker

```
$ docker build -t <image-name> .
$ docker run --rm -itd -p 8001:8001 --env-file=settings/google.sso.env <image-name>
```


# TODO

- DockerコンテナのOSをRedHat7にする
- RedHat7の環境でインストール手順を確立する
