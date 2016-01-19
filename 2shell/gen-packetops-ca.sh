#!/bin/bash


## TODO: implement using openssl...

#export PW=`cat ca-password`
#
#mkdir -p out

## Create a self signed key pair root CA certificate.
#keytool -genkeypair -v \
#  -alias packetopsca \
#  -dname "CN=packetopsCA, OU=packetops.net, O=packetops ltd, L=London, ST=London, C=GB" \
#  -keystore out/packetops.jks \
#  -keypass:env PW \
#  -storepass:env PW \
#  -keyalg RSA \
#  -keysize 4096 \
#  -ext KeyUsage="keyCertSign" \
#  -ext crlDistributionPoints="URI:https://packetops.net/intermediate.crl.pem" \
#  -ext BasicConstraints:"critical=ca:true" \
#  -validity 9999
#
## Export the exampleCA public certificate so that it can be used in trust stores..
#keytool -export -v \
#  -alias packetopsca \
#  -file out/packetopsca.crt \
#  -keypass:env PW \
#  -storepass:env PW \
#  -keystore out/packetops.jks \
#  -rfc
