#!/bin/bash

# TODO: implement using openssl CLI

#export PW_STORE=`cat ca-password`
#export PW_SERVER=`cat server-cert-password`
#export PW=`cat server-cert-password`
#
#_hostname=${1:?hostname must be specified as first argument to this script}
#
#REGEX_HOST="[a-z0-9-]*\.[a-z]+"
#REGEX_IP="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[1-9]{1,3}$"
#
#if [[ !($_hostname =~ $REGEX_IP) && !($_hostname =~ $REGEX_HOST) ]] ; then
#  echo "paramter '$_hostname' : does not appear to be a valid hostname or IP address - exiting" > /dev/stderr
#  exit 1
#fi
#
#keytool -genkeypair -v \
#  -alias $_hostname
#  -dname "CN=$_hostname, OU=packetops.net, O=packetops ltd, L=London, ST=London, C=GB" \
#  -keystore out/packetops.jks \
#  -keypass:env PW_SERVER \
#  -storepass:env PW_STORE \
#  -keyalg RSA \
#  -keysize 4096 \
#  -ext ExtendedkeyUsage="serverAuth,clientAuth" \
#  -ext crlDistributionPoints="URI:https://packetops.net/intermediate.crl.pem" \
#  -ext BasicConstraints:"critical=ca:true" \
#  -validity 9999
#
#
#
### Export the exampleCA public certificate so that it can be used in trust stores..
##keytool -export -v \
##  -alias packetopsca \
##  -file out/packetopsca.crt \
##  -keypass:env PW \
##  -storepass:env PW \
##  -keystore out/packetops-ca.jks \
##  -rfc
