# ---------- Stage 1: build the jar with Maven ----------
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace

# Download dependencies first so Docker can cache this layer between builds
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q package -DskipTests

# ---------- Stage 2: small runtime image with only the JRE ----------
FROM eclipse-temurin:17-jre
WORKDIR /app

# Run as a normal user, not root; /app/data holds the CSV history
RUN useradd --system --uid 1001 --home-dir /app phishguard \
    && mkdir -p /app/data \
    && chown -R phishguard /app
COPY --from=build /workspace/target/phishguard.jar /app/app.jar
USER phishguard

ENV HISTORY_FILE=/app/data/scan_history.csv \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+UseSerialGC"

# Render and Railway set PORT; Spring reads it via server.port=${PORT:8080}
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
