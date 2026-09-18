package co.edu.eci.blueprints.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/blueprints")
@Tag(name = "BluePrints", description = "Consulta y creación de planos. Requiere un JWT con el scope indicado.")
public class BlueprintController {

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_blueprints.read')")
    @Operation(summary = "Listar blueprints", description = "Devuelve los blueprints disponibles. Requiere el scope `blueprints.read`.")
    @SecurityRequirement(name = "bearer-jwt")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Listado de blueprints", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = BlueprintResponse.class)))),
            @ApiResponse(responseCode = "401", description = "Token JWT ausente, inválido o expirado"),
            @ApiResponse(responseCode = "403", description = "El token no tiene el scope blueprints.read")
    })
    public List<Map<String, String>> list() {
        return List.of(
            Map.of("id", "b1", "name", "Casa de campo"),
            Map.of("id", "b2", "name", "Edificio urbano")
        );
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_blueprints.write')")
    @Operation(summary = "Crear un blueprint", description = "Crea un blueprint a partir de su nombre. Requiere el scope `blueprints.write`.")
    @SecurityRequirement(name = "bearer-jwt")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, description = "Datos del blueprint a crear.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = CreateBlueprintRequest.class), examples = @ExampleObject(value = "{\"name\":\"Casa de playa\"}")))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Blueprint creado", content = @Content(mediaType = "application/json", schema = @Schema(implementation = BlueprintResponse.class))),
            @ApiResponse(responseCode = "400", description = "Cuerpo de la solicitud inválido"),
            @ApiResponse(responseCode = "401", description = "Token JWT ausente, inválido o expirado"),
            @ApiResponse(responseCode = "403", description = "El token no tiene el scope blueprints.write")
    })
    public Map<String, String> create(@RequestBody Map<String, String> in) {
        return Map.of("id", "new", "name", in.getOrDefault("name", "nuevo"));
    }

    @Schema(name = "BlueprintResponse", description = "Representación resumida de un blueprint.")
    public record BlueprintResponse(@Schema(description = "Identificador del blueprint.", example = "b1") String id, @Schema(description = "Nombre del blueprint.", example = "Casa de campo") String name) {}

    @Schema(name = "CreateBlueprintRequest", description = "Datos requeridos para crear un blueprint.")
    public record CreateBlueprintRequest(@Schema(description = "Nombre del nuevo blueprint.", example = "Casa de playa") String name) {}
}
