FROM eclipse-temurin:17-jdk-alpine AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN apk add --no-cache maven && mvn package -DskipTests -q

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN addgroup -S sentinela && adduser -S sentinela -G sentinela

COPY --from=builder /app/target/sentinela-server-1.0.0.jar app.jar
COPY src/main/resources/keys /app/keys

RUN chown -R sentinela:sentinela /app
USER sentinela

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-Dspring.profiles.active=prod", \
  "-jar", "app.jar"]
