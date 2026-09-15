#!/bin/sh
# Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0
set -eu
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"
./mvnw -B -ntp package -DskipTests
exec ./mvnw -B -ntp org.codehaus.mojo:exec-maven-plugin:3.6.3:java \
  -Dexec.mainClass=io.github.suengineering.keycloak.oid4vp.it.Oid4vpDemo \
  -Dexec.classpathScope=test -Dexec.cleanupDaemonThreads=false
