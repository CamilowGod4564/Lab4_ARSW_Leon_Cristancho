package co.edu.eci.blueprints.auth;

import co.edu.eci.blueprints.security.InMemoryUserService;
import co.edu.eci.blueprints.security.RsaKeyProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticación", description = "Obtención de tokens JWT para acceder a los recursos protegidos.")
public class AuthController {

    private final JwtEncoder encoder;
    private final InMemoryUserService userService;
    private final RsaKeyProperties props;

    public AuthController(JwtEncoder encoder, InMemoryUserService userService, RsaKeyProperties props) {
        this.encoder = encoder;
        this.userService = userService;
        this.props = props;
    }

    @Schema(name = "LoginRequest", description = "Credenciales del usuario registrado.")
    public record LoginRequest(
            @Schema(description = "Nombre de usuario.", example = "reader") String username,
            @Schema(description = "Contraseña del usuario.", example = "reader123") String password) {}

    @Schema(name = "TokenResponse", description = "Token de acceso emitido tras una autenticación exitosa.")
    public record TokenResponse(
            @Schema(description = "JWT que se debe enviar como Bearer token.", example = "eyJhbGciOiJSUzI1NiJ9...") String access_token,
            @Schema(description = "Tipo de token.", example = "Bearer") String token_type,
            @Schema(description = "Tiempo de vida del token, en segundos.", example = "3600") long expires_in) {}

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión", description = "Valida las credenciales y devuelve un JWT para consumir los endpoints protegidos.")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Autenticación exitosa", content = @Content(mediaType = "application/json", schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas", content = @Content(mediaType = "application/json", examples = @ExampleObject(value = "{\"error\":\"invalid_credentials\"}"))),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida")
    })
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        if (!userService.isValid(req.username(), req.password())) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_credentials"));
        }

        Instant now = Instant.now();
        long ttl = props.tokenTtlSeconds() != null ? props.tokenTtlSeconds() : 3600;
        Instant exp = now.plusSeconds(ttl);

        String scope = userService.scopesOf(req.username());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .issuedAt(now)
                .expiresAt(exp)
                .subject(req.username())
                .claim("scope", scope)
                .build();

        JwsHeader jws = JwsHeader.with(() -> "RS256").build();
        String token = this.encoder.encode(JwtEncoderParameters.from(jws, claims)).getTokenValue();

        return ResponseEntity.ok(new TokenResponse(token, "Bearer", ttl));
    }
}
