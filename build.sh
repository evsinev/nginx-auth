#!/usr/bin/env bash
set -eux
mvn clean install assembly:single

open target
open https://github.com/evsinev/nginx-auth/releases

