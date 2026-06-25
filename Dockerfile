# syntax=docker/dockerfile:1.7

# -------- Stage 1: build the GraalVM native image --------
FROM ghcr.io/graalvm/native-image-community:21 AS build

WORKDIR /workspace

# Copy the Maven wrapper + every module POM first so dependency resolution is cached
# independently of source changes. All four module POMs are needed because the reactor
# parent lists them; Maven validates the module tree even for a `-pl` subset build.
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY etchlog-core/pom.xml etchlog-core/
COPY etchlog-server/pom.xml etchlog-server/
COPY etchlog-spring-boot-starter/pom.xml etchlog-spring-boot-starter/
COPY etchlog-cli/pom.xml etchlog-cli/

# Warm the dependency cache. go-offline pulls plugins + deps for the server build graph.
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -q -ntp -pl etchlog-core,etchlog-server -am dependency:go-offline

# Now copy sources and build the native image for the server module (+ its core dependency).
COPY etchlog-core/src etchlog-core/src
COPY etchlog-server/src etchlog-server/src

RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -q -ntp -pl etchlog-server -am \
      -Pnative -DskipTests clean package

# The native-maven-plugin emits the binary as the configured imageName (etchlog-server).
RUN cp etchlog-server/target/etchlog-server /workspace/etchlog

# -------- Stage 2: minimal runtime --------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Distroless 'nonroot' already runs as uid 65532; no shell, no package manager.
WORKDIR /app
COPY --from=build /workspace/etchlog /app/etchlog

# The server binds inside the container; the reverse proxy / host maps the port.
EXPOSE 8080

# Spring Boot Actuator readiness is the truth source for "ready to serve". distroless has no
# curl/wget, so the orchestrator probes health by exec-ing the binary's own `--healthcheck` flag
# (see docker-compose.yml and Healthcheck.java).
ENTRYPOINT ["/app/etchlog"]
