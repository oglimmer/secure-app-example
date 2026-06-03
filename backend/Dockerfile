# ---- build stage ----
FROM eclipse-temurin:25-jdk AS build
WORKDIR /app

# Cache dependencies first: copy only what dependency resolution needs.
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN ./mvnw -B -q dependency:go-offline

# Then the sources.
COPY src/ src/
RUN ./mvnw -B -q clean package -DskipTests

# ---- runtime stage ----
FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
