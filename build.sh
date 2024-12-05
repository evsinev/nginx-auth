#!/usr/bin/env bash
set -eux
mvn clean install assembly:single

mv target/nginx-auth-1.0-3-SNAPSHOT-jar-with-dependencies.jar target/nginx-auth-1.0-3-SNAPSHOT-jar-with-dependencies.zip

open target
open https://github.com/evsinev/nginx-auth/releases

