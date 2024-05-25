# {{ package_name }}




# Use hatch

Install the env with all lib

```
hatch env create
```

Start Env

```
hatch shell
```


# Configuration

In order to be able to generate the certicat you need to define
- a user
- a password
- a passphrase

The password will be used to
- check the user authenicated
- decrypt the passphrase


For example if you choose

user: bob
password: incroyableeponge
passphrase: supersecret

you need:
- encrypt the passphrase
- generate an htpasswd


openssl genrsa -out ./tmp/ca/bob/private/cakey.pem 4096
openssl req -new -key ./tmp/ca/bob/private/cakey.pem \
    -out ./tmp/ca/bob/careq.pem -passin pass:supersecret \
    -subj "/countryName=FR/stateOrProvinceName=Rhone Alpes/organizationName=Akretion/organizationalUnitName=IT/commonName=Akretion/emailAddress=akretion@example.org/"
openssl ca -config ./tmp/ca/bob/openssl.cnf \
    -create_serial -out ./tmp/ca/bob/cacert.pem -days 3650 \
    -batch -key supersecret -keyfile ./tmp/ca/bob//private/cakey.pem -selfsign -extensions v3_ca\
    -infiles ./tmp/ca/bob/careq.pem
