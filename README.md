# certbot-dns-namecom

[Name.com](https://www.name.com) DNS Authenticator plugin for
[Certbot](https://certbot.eff.org).

This plugin automates the process of completing a `dns-01` challenge by
creating (and removing) TXT records using the Name.com API.


## Installation

```bash
pip install certbot-dns-namecom
```

## Credentials

Obtain an API token from your Name.com account at
https://www.name.com/account/settings/api.

Create a credentials file (e.g. `~/.secrets/namecom.ini`):

```ini
# Name.com API credentials used by Certbot
dns_namecom_username = myusername
dns_namecom_token = 0123456789abcdef0123456789abcdef01234567
```

Protect it:

```bash
chmod 600 ~/.secrets/namecom.ini
```

## Usage

```bash
certbot certonly \
  --dns-namecom-credentials ~/.secrets/namecom.ini \
  -d example.com
```

Wildcard certificate:

```bash
certbot certonly \
  --dns-namecom-credentials ~/.secrets/namecom.ini \
  -d example.com \
  -d '*.example.com'
```

Custom propagation delay (default: 30s):

```bash
certbot certonly \
  --dns-namecom-credentials ~/.secrets/namecom.ini \
  --dns-namecom-propagation-seconds 60 \
  -d example.com
```

## Docker

Ideally used with SWAG:
[linuxserver/swag](https://github.com/linuxserver/docker-swag) image.

Use the `universal-package-install` mod in your `docker-compose.yml`:
```yaml
services:
  swag:
    image: lscr.io/linuxserver/swag:latest
    environment:
      - DOCKER_MODS=linuxserver/mods:universal-package-install
      - INSTALL_PIP_PACKAGES=certbot-dns-namecom
      - VALIDATION=dns
      - DNSPLUGIN=namecom
      # ... other SWAG env vars
    volumes:
      - ./config:/config
```

Don't forget to create the credentials file at `dns-conf/namecom.ini`

