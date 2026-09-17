# Escuela Colombiana de Ingeniería Julio Garavito
## Arquitectura de Software – ARSW
### Laboratorio – Parte 2: BluePrints API con Seguridad JWT (OAuth 2.0)


## Participantes
### - Jeyder Nicolay León Lancheros
### - Juan Camilo Cristancho Velasquez

# Actividades propuestas
1. Revisar el código de configuración de seguridad (`SecurityConfig`) e identificar cómo se definen los endpoints públicos y protegidos.

En la clase SecurityConfig se definen todos los aspectos en temas de seguridad de endpoints, decodificacion de contraseñas y de tokens JWT. Para entender como
funciona vamos a separarla por bloques.


#### Seguridad de EndPoints

Este metodo define las reglas de seguridad de nuestra api, cada vez que se arranca la aplicacion se ejecuta y define 
quien puede pasar, quien no y con qué restricciones.
```java
  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/auth/login").permitAll()
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                .requestMatchers("/api/**").hasAnyAuthority("SCOPE_blueprints.read", "SCOPE_blueprints.write")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
  ```
Para empezar, desactiva CSRF, ya que como usamos tokens para autenticacion no aplica (CSRF usa cookies) por eso lo desactivamos.
```java
.csrf(csrf -> csrf.disable())
  ```

Luego empiezan todas las reglas de seguridad de nuestra api, aca definimos las rutas permitidas y para quienes lo están.

```java
.authorizeHttpRequests(auth -> auth
```

Empezamos definiendo las rutas públicas, las cuales son health que sirve como endpoint de monitoreo de que la api esté levantada, 
y el endpoint de login, el cual necesitamos que sea público para que todo el mundo se pueda autenticar e ingresar a los endpoints protegidos.
```java
.requestMatchers("/actuator/health", "/auth/login").permitAll()
```
Seguimos con la documentacion en Swagger, la cual para visualizar los endpoints de la mejor manera es necesario que sea pública,
asi podemos probar los demás endpoints publicos y protegidos.
```java
.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
```
Para los endpoints protegidos, aplica para todo los endpoints bajo /api/** que tengan al menos uno de los dos scopes disponibles

Scopes: Son permisos definidos que viajan a traves del token JWT y que al momento de autenticar le da permisos al usuario, para este 
ejercicio hay permisos de lectura y escritura.
```java
.requestMatchers("/api/**").hasAnyAuthority("SCOPE_blueprints.read", "SCOPE_blueprints.write")
```
```java
```


2. Explorar el flujo de login y analizar las claims del JWT emitido.
3. Extender los scopes (`blueprints.read`, `blueprints.write`) para controlar otros endpoints de la API, del laboratorio P1 trabajado.
4. Modificar el tiempo de expiración del token y observar el efecto.
5. Documentar en Swagger los endpoints de autenticación y de negocio.