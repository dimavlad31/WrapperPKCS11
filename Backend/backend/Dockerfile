FROM maven:3.8.5-openjdk-17 AS builder

WORKDIR /app

COPY . ./


RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim AS runner

WORKDIR /app

COPY --from=builder /app/key.bin ./
RUN echo "KEY_BIN_PATH=/app/key.bin" > .env

FROM openjdk:17-jdk-slim

WORKDIR /app

COPY --from=builder /app/target/*.jar app.jar
COPY --from=runner /app/.env ./
COPY --from=runner /app/key.bin ./



CMD ["java", "-jar", "app.jar"]