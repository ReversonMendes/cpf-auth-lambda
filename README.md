Building the Java Lambda

Prerequisites:
- Java 11 JDK
- Maven

From PowerShell (Windows):

```powershell
cd lambda-src
mvn clean package -DskipTests
# The shaded jar will be at target/cpf-auth-lambda-1.0.0.jar (or similar)
# Create a zip containing the jar and any bootstrap files required by your handler
Compress-Archive -Path target\cpf-auth-lambda-1.0.0.jar -DestinationPath ..\auth_handler.java.zip -Force
```

Note: The Terraform `data.archive_file` expects `auth_handler.java.zip` in the repo root. Adjust `variables.tf` if you change the paths.

Handler class: `com.example.lambda.AuthHandler`

Environment variables used by the Lambda:
- `COGNITO_USER_POOL_ID` (provided by Terraform)
- `JWT_SECRET_KEY` (provided by Terraform/Secrets Manager)

Security note: do not commit `auth_handler.java.zip` with real secrets.
