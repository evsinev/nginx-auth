#!/usr/bin/env bash
set -eux
mvn clean package

open target
open https://github.com/evsinev/nginx-auth/releases

