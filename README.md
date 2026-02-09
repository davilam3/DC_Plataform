src/main/java/ec/edu/ups/icc/portafolio/config/
├── security/
│   ├── JwtAuthenticationEntryPoint.java
│   ├── JwtAuthenticationFilter.java
│   ├── JwtProperties.java
│   ├── JwtUtil.java
│   ├── SecurityConfig.java
│   ├── AppointmentSecurity.java     
│   ├── PortfolioSecurity.java          
│   ├── ProjectSecurity.java            
│   ├── AvailabilitySecurity.java       
│   └──UserSecurity.java                 
├── EmailConfig.java
└── DataInitializer.java
└── JacksonConfig.java
├── modules/
│ ├── appointments/ # Gestión de citas
│ │ ├── controllers/
│ │ │ └── AppointmentController.java
│ │ ├── dtos/
│ │ │ ├── AppointmentRequestDto.java
│ │ │ └── AppointmentResponseDto.java
│ │ ├── models/
│ │ │ ├── AppointmentEntity.java
│ │ │ └── AppointmentStatus.java
│ │ ├── repositories/
│ │ │ └── AppointmentRepository.java
│ │ └── services/
│ │ ├── AppointmentMapper.java
│ │ ├── AppointmentService.java
│ │ └── AppointmentServiceImpl.java
│ ├── auth/ # Autenticación
│ │ ├── controllers/
│ │ │ └── AuthController.java
│ │ ├── dtos/
│ │ │ ├── AuthResponseDto.java
│ │ │ ├── LoginRequestDto.java
│ │ │ └── RegisterRequestDto.java
│ │ └── services/
│ │ └── AuthService.java
│ ├── availabilities/ # Disponibilidad
│ │ ├── controllers/
│ │ │ └── Ac.java
│ │ ├── dtos/
│ │ │ ├── RequAvailabilityestDto.java
│ │ │ └── AvailabilityResponseDto.java
│ │ ├── models/
│ │ │ ├── AvailabilityEntity.java
│ │ │ ├── DayOfWeek.java
│ │ │ └── Modality.java
│ │ ├── repositories/
│ │ │ └── AvailabilityRepository.java
│ │ └── services/
│ │ ├── AvailabilityMapper.java
│ │ ├── AvailabilityService.java
│ │ └── AvailabilityServiceImpl.java
│ ├── notifications/ # Sistema de notificaciones
│ │ ├── controllers/
│ │ │ └── NotificationController.java
│ │ ├── dtos/
│ │ │ ├── NotificationRequestDto.java
│ │ │ └── NotificationResponseDto.java
│ │ ├── models/
│ │ │ ├── NotificationEntity.java
│ │ │ └── NotificationType.java
│ │ ├── repositories/
│ │ │ └── NotificationRepository.java
│ │ ├── security/
│ │ │ └── NotificationSecurity.java
│ │ └── services/
│ │ ├── EmailService.java
│ │ ├── NotificationMapper.java
│ │ ├── NotificationScheduler.java
│ │ ├── NotificationService.java
│ │ └── NotificationServiceImpl.java
│ ├── portfolios/ # Portafolios profesionales
│ │ ├── controllers/
│ │ │ └── PortfolioController.java
│ │ ├── dtos/
│ │ │ ├── PortfolioRequestDto.java
│ │ │ └── PortfolioResponseDto.java
│ │ ├── models/
│ │ │ ├── PortfolioEntity.java
│ │ │ └── Speciality.java
│ │ ├── repositories/
│ │ │ └── PortfolioRepository.java
│ │ └── services/
│ │ ├── PortfolioMapper.java
│ │ ├── PortfolioService.java
│ │ └── PortfolioServiceImpl.java
│ ├── projects/ # Proyectos
│ │ ├── controllers/
│ │ │ └── ProjectController.java
│ │ ├── dtos/
│ │ │ ├── ProjectRequestDto.java
│ │ │ └── ProjectResponseDto.java
│ │ ├── models/
│ │ │ ├── ParticipationType.java
│ │ │ ├── ProjectEntity.java
│ │ │ └── ProjectType.java
│ │ ├── repositories/
│ │ │ └── ProjectRepository.java
│ │ └── services/
│ │ ├── ProjectMapper.java
│ │ ├── ProjectService.java
│ │ └── ProjectServiceImpl.java
│ └── users/ # Gestión de usuarios
│ ├── controllers/  
│ │ └── UserController.java
│ ├── dtos/
│ │ ├── UserRequestDto.java
│ │ ├── UserResponseDto.java
│ │ └── UserUpdateDto.java
│ ├── models/
│ │ ├── RoleEntity.java
│ │ ├── RoleName.java
│ │ └── UserEntity.java
│ ├── repositories/
│ │ ├── RoleRepository.java
│ │ └── UserRepository.java
│ └── services/
│ ├── UserDetailsImpl.java
│ ├── UserDetailsServiceImpl.java
│ ├── UserMapper.java
│ ├── UserService.java
│ └── UserServiceImpl.java
└── PortafolioApplication.java # Clase principal

src/main/resources/
├── static/
├── templates/
└── application.yaml


### JwtAuthenticationEntryPoint.java

```java
package ec.edu.ups.icc.portafolio.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import ec.edu.ups.icc.portafolio.shared.exceptions.response.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        logger.error("Error de autenticación: {}", authException.getMessage());

        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Token de autenticación inválido o no proporcionado. " +
                        "Debe incluir un token válido en el header Authorization: Bearer <token>",
                request.getRequestURI());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
```
### JwtAuthenticationFilter.java

```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtProperties jwtProperties;

    public JwtAuthenticationFilter(
            JwtUtil jwtUtil,
            UserDetailsServiceImpl userDetailsService,
            JwtProperties jwtProperties
    ) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.jwtProperties = jwtProperties;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getServletPath();

        // 🔓 Endpoints públicos
        if (isPublicEndpoint(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwt = getJwtFromRequest(request);

            if (jwt != null && jwtUtil.validateToken(jwt)) {

                String email = jwtUtil.getEmailFromToken(jwt);

                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(email);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authentication.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );

                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);
            }

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            logger.error("Error procesando JWT", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(jwtProperties.getHeader());

        if (!StringUtils.hasText(bearerToken)) {
            return null;
        }

        if (!bearerToken.startsWith(jwtProperties.getPrefix() + " ")) {
            return null;
        }

        return bearerToken.substring(
                (jwtProperties.getPrefix() + " ").length()
        );
    }

    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/api/auth/")
                || path.startsWith("/swagger-ui/")
                || path.startsWith("/v3/api-docs")
                || path.startsWith("/actuator/health");
    }
}

```

### JwtProperties.java
```java

package ec.edu.ups.icc.portafolio.config.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private Long expiration;
    private Long refreshExpiration;
    private String issuer;
    private String header;
    private String prefix;

    // Getters y Setters
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Long getExpiration() {
        return expiration;
    }

    public void setExpiration(Long expiration) {
        this.expiration = expiration;
    }

    public Long getRefreshExpiration() {
        return refreshExpiration;
    }

    public void setRefreshExpiration(Long refreshExpiration) {
        this.refreshExpiration = refreshExpiration;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }
}
```

### JwtUtil.java

```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    private final JwtProperties jwtProperties;
    private final SecretKey key;

    public JwtUtil(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }

    public String generateToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getExpiration());

        String roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(String.valueOf(userPrincipal.getId()))
                .claim("email", userPrincipal.getEmail())
                .claim("name", userPrincipal.getName())
                .claim("roles", roles)
                .issuer(jwtProperties.getIssuer())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenFromUserDetails(UserDetailsImpl userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getExpiration());

        String roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(String.valueOf(userDetails.getId()))
                .claim("email", userDetails.getEmail())
                .claim("name", userDetails.getName())
                .claim("roles", roles)
                .issuer(jwtProperties.getIssuer())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return Long.parseLong(claims.getSubject());
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.get("email", String.class);
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(authToken);
            return true;

        } catch (SignatureException ex) {
            logger.error("Firma JWT inválida: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            logger.error("Token JWT malformado: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.error("Token JWT expirado: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("Token JWT no soportado: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string está vacío: {}", ex.getMessage());
        }

        return false;
    }
}
```

### SecurityConfig.java

```java
package ec.edu.ups.icc.portafolio.config.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:4200",
                "https://dc-plataform.onrender.com"));

        config.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept"));

        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // ======== ENDPOINTS PÚBLICOS ========
                        // Auth
                        .requestMatchers("/api/auth/**").permitAll()

                        // Portfolios (públicos para explorar)
                        .requestMatchers(HttpMethod.GET, "/api/portfolios").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/speciality/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/available").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/search").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/user/{userId}").authenticated()

                        // Projects (públicos para explorar)
                        .requestMatchers(HttpMethod.GET, "/api/projects").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/portfolios/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/projects/portfolio/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/projects/type/{projectType}").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/projects/search").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/projects/portfolio/{portfolioId}/count").authenticated()

                        // Availabilities (públicos para explorar)
                        .requestMatchers(HttpMethod.GET, "/api/availabilities/programmer/{programmerId}").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/availabilities/programmer/{programmerId}/available")
                        .permitAll()

                        // ======== ADMIN ENDPOINTS ========
                        // Users - Solo ADMIN
                        .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/users").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/users/*").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/users/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/users/search").hasRole("ADMIN")

                        // Appointments - ADMIN ve todo
                        .requestMatchers(HttpMethod.GET, "/api/appointments").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/appointments/programmer/{programmerId}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/appointments/client/{clientId}").hasRole("ADMIN")

                        // Availabilities - ADMIN gestiona cualquier disponibilidad
                        .requestMatchers(HttpMethod.POST, "/api/availabilities").hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/availabilities/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/availabilities/{id}").hasRole("ADMIN")

                        // Notifications - ADMIN panel de control
                        .requestMatchers(HttpMethod.GET, "/api/notifications").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/notifications").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/notifications/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/notifications/user/{userId}").hasRole("ADMIN")

                        // ======== PROGRAMMER ENDPOINTS ========
                        // Portfolios - PROGRAMMER gestiona solo el suyo
                        .requestMatchers(HttpMethod.POST, "/api/portfolios").hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/portfolios/{id}").hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.DELETE, "/api/portfolios/{id}").hasAnyRole("ADMIN", "PROGRAMMER")

                        // Projects - PROGRAMMER gestiona solo sus proyectos
                        .requestMatchers(HttpMethod.POST, "/api/projects").hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/projects/{id}").hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.DELETE, "/api/projects/{id}").hasAnyRole("ADMIN", "PROGRAMMER")

                        // Appointments - PROGRAMMER gestiona sus citas
                        .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                        .hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                        .hasAnyRole("ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                        .hasAnyRole("ADMIN", "PROGRAMMER")

                        // ======== USER ENDPOINTS ========
                        // Appointments - USER crea y gestiona sus citas
                        .requestMatchers(HttpMethod.POST, "/api/appointments").hasAnyRole("USER", "ADMIN", "PROGRAMMER")
                        .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                        .hasAnyRole("USER", "ADMIN", "PROGRAMMER")

                        // Users - Cada usuario gestiona su perfil
                        .requestMatchers(HttpMethod.GET, "/api/users/{id}").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/users/{id}").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/api/users/{id}").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/users/programmers").permitAll()

                        // Notifications - Cada usuario gestiona sus notificaciones
                        .requestMatchers(HttpMethod.GET, "/api/notifications/user/{userId}").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/notifications/user/{userId}/unread").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/notifications/user/{userId}/count-unread")
                        .authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/notifications/*/mark-as-read").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/notifications/user/{userId}/mark-all-as-read")
                        .authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/notifications/types").hasRole("ADMIN")

                        // ======== ENDPOINTS COMPARTIDOS ========
                        .requestMatchers(HttpMethod.GET, "/api/appointments/upcoming").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/appointments/status/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/appointments/search").authenticated()

                        // Cualquier otra solicitud requiere autenticación
                        .anyRequest().authenticated());

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

```

### AppointmentSecurity.java   
```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.appointments.repositories.AppointmentRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("appointmentSecurity")
public class AppointmentSecurity {
    
    private final AppointmentRepository appointmentRepository;
    
    public AppointmentSecurity(AppointmentRepository appointmentRepository) {
        this.appointmentRepository = appointmentRepository;
    }
    
    public boolean isProgrammer(Long programmerId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        // Verificar si el usuario actual es el programador
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return currentUserId.equals(programmerId) || isAdmin;
    }
    
    public boolean isProgrammerForAppointment(Long appointmentId) {
        return appointmentRepository.findById(appointmentId)
                .map(appointment -> isProgrammer(appointment.getProgrammer().getId()))
                .orElse(false);
    }
    
    public boolean isClientForAppointment(Long appointmentId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        return appointmentRepository.findById(appointmentId)
                .map(appointment -> appointment.getClient().getId().equals(currentUserId))
                .orElse(false);
    }
    
    public boolean isClient(Long clientId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return currentUserId.equals(clientId) || isAdmin;
    }
}
```

### PortfolioSecurity.java    
```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.portfolios.repositories.PortfolioRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("portfolioSecurity")
public class PortfolioSecurity {
    
    private final PortfolioRepository portfolioRepository;
    
    public PortfolioSecurity(PortfolioRepository portfolioRepository) {
        this.portfolioRepository = portfolioRepository;
    }
    
    public boolean isOwner(Long portfolioId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        // Verificar si el usuario actual es el dueño del portfolio
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return portfolioRepository.findById(portfolioId)
                .map(portfolio -> portfolio.getUser().getId().equals(currentUserId) || isAdmin)
                .orElse(false);
    }
}
```

### ProjectSecurity.java   
```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.projects.repositories.ProjectRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("projectSecurity")
public class ProjectSecurity {
    
    private final ProjectRepository projectRepository;
    
    public ProjectSecurity(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }
    
    public boolean isPortfolioOwner(Long projectId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        // Verificar si el usuario actual es el dueño del portfolio del proyecto
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return projectRepository.findById(projectId)
                .map(project -> project.getPortfolio().getUser().getId().equals(currentUserId) || isAdmin)
                .orElse(false);
    }
}
```

### AvailabilitySecurity.java   
```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.availabilities.repositories.AvailabilityRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("availabilitySecurity")
public class AvailabilitySecurity {
    
    private final AvailabilityRepository availabilityRepository;
    
    public AvailabilitySecurity(AvailabilityRepository availabilityRepository) {
        this.availabilityRepository = availabilityRepository;
    }
    
    public boolean isOwner(Long availabilityId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        // Verificar si el usuario actual es el programador de la disponibilidad
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return availabilityRepository.findById(availabilityId)
                .map(availability -> availability.getProgrammer().getId().equals(currentUserId) || isAdmin)
                .orElse(false);
    }
}
```

### UserSecurity.java           
```java
package ec.edu.ups.icc.portafolio.config.security;

import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("userSecurity")
public class UserSecurity {
    
    public boolean isSelf(Long targetUserId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();
        
        // Verificar si el usuario actual es el mismo que el objetivo
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        return currentUserId.equals(targetUserId) || isAdmin;
    }
}
```

### EmailConfig.java

```java
package ec.edu.ups.icc.portafolio.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
public class EmailConfig {

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);

        // Estos valores se sobreescriben con application.yml
        mailSender.setUsername("${spring.mail.username}");
        mailSender.setPassword("${spring.mail.password}");

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "false");

        return mailSender;
    }
}
```

### DataInitializer.java

```java
package ec.edu.ups.icc.portafolio.config.Datos;

// import org.springframework.boot.CommandLineRunner;
// import org.springframework.context.annotation.*;
// import org.springframework.core.annotation.Order;

// import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
// import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
// import ec.edu.ups.icc.portafolio.modules.users.repositories.RoleRepository;

// @Configuration
// public class DataInitializer {

//     @Bean
//     @Order(1)
//     public CommandLineRunner initRoles(RoleRepository roleRepository) {
//         return args -> {
//             // Verifica si los roles ya existen
//             if (roleRepository.count() == 0) {
//                 System.out.println("📝 Creando roles por defecto...");
                
//                 // Crear rol ADMIN
//                 RoleEntity adminRole = new RoleEntity();
//                 adminRole.setName(RoleName.ROLE_ADMIN);
//                 adminRole.setDescription("Administrador del sistema");
//                 roleRepository.save(adminRole);
                
//                 // Crear rol PROGRAMMER
//                 RoleEntity programmerRole = new RoleEntity();
//                 programmerRole.setName(RoleName.ROLE_PROGRAMMER);
//                 programmerRole.setDescription("Programador con portafolio");
//                 roleRepository.save(programmerRole);
                
//                 // Crear rol USER
//                 RoleEntity userRole = new RoleEntity();
//                 userRole.setName(RoleName.ROLE_USER);
//                 userRole.setDescription("Usuario externo que agenda asesorías");
//                 roleRepository.save(userRole);
                
//                 System.out.println("✅ Roles creados exitosamente");
//             } else {
//                 System.out.println("✅ Roles ya existen en la base de datos");
//             }
//         };
//     }
    
// }
import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.RoleRepository;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    @Order(1)
    public CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
            // Verifica si los roles ya existen
            if (roleRepository.count() == 0) {
                System.out.println("📝 Creando roles por defecto...");
                
                // Crear rol ADMIN
                RoleEntity adminRole = new RoleEntity();
                adminRole.setName(RoleName.ROLE_ADMIN);
                adminRole.setDescription("Administrador del sistema");
                roleRepository.save(adminRole);
                
                // Crear rol PROGRAMMER
                RoleEntity programmerRole = new RoleEntity();
                programmerRole.setName(RoleName.ROLE_PROGRAMMER);
                programmerRole.setDescription("Programador con portafolio");
                roleRepository.save(programmerRole);
                
                // Crear rol USER
                RoleEntity userRole = new RoleEntity();
                userRole.setName(RoleName.ROLE_USER);
                userRole.setDescription("Usuario externo que agenda asesorías");
                roleRepository.save(userRole);
                
                System.out.println("✅ Roles creados exitosamente");
            } else {
                System.out.println("✅ Roles ya existen en la base de datos");
            }
        };
    }
    
    @Bean
    @Order(2)
    public CommandLineRunner initAdminUser(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        return args -> {
            // Email del admin por defecto (puedes cambiarlo)
            String adminEmail = "admin@portafolio.com";
            
            // Verificar si ya existe el admin
            if (userRepository.findByEmail(adminEmail).isEmpty()) {
                System.out.println(" Creando usuario administrador por defecto...");
                
                // Buscar rol ADMIN
                RoleEntity adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Rol ADMIN no encontrado"));
                
                // Crear usuario admin
                UserEntity adminUser = new UserEntity();
                adminUser.setName("Administrador del Sistema");
                adminUser.setEmail(adminEmail);
                adminUser.setPassword(passwordEncoder.encode("Admin123"));
                adminUser.setBio("Administrador principal del sistema");
                
                // Asignar rol ADMIN
                Set<RoleEntity> roles = new HashSet<>();
                roles.add(adminRole);
                adminUser.setRoles(roles);
                
                userRepository.save(adminUser);
                
                System.out.println(" Usuario administrador creado exitosamente");
                System.out.println(" Email: " + adminEmail);
                System.out.println(" Contraseña: Admin123");
                System.out.println(" IMPORTANTE: Cambia la contraseña después del primer login");
            } else {
                System.out.println("Usuario administrador ya existe");
            }
        };
    }
}
```

### JacksonConfig.java

```java
package ec.edu.ups.icc.portafolio.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}

```

## Citas (/modules/appointments/)
### AppointmentController.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.controllers;

import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentRequestDto;
import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentResponseDto;
import ec.edu.ups.icc.portafolio.modules.appointments.services.AppointmentService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

    private final AppointmentService appointmentService;

    public AppointmentController(AppointmentService appointmentService) {
        this.appointmentService = appointmentService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')") // Solo ADMIN ve todas las citas
    public ResponseEntity<Page<AppointmentResponseDto>> getAllAppointments(Pageable pageable) {
        return ResponseEntity.ok(appointmentService.findAll(pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<AppointmentResponseDto> getAppointmentById(@PathVariable Long id) {
        return ResponseEntity.ok(appointmentService.findById(id));
    }

    @GetMapping("/programmer/{programmerId}")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isProgrammer(#programmerId)")
    public ResponseEntity<List<AppointmentResponseDto>> getAppointmentsByProgrammer(
            @PathVariable Long programmerId) {
        return ResponseEntity.ok(appointmentService.findByProgrammerId(programmerId));
    }

    @GetMapping("/client/{clientId}")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isClient(#clientId)")
    public ResponseEntity<List<AppointmentResponseDto>> getAppointmentsByClient(
            @PathVariable Long clientId) {
        return ResponseEntity.ok(appointmentService.findByClientId(clientId));
    }

    @PostMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('PROGRAMMER')")
    public ResponseEntity<AppointmentResponseDto> createAppointment(
            @Valid @RequestBody AppointmentRequestDto appointmentDto) {
        AppointmentResponseDto created = appointmentService.create(appointmentDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}/approve")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isProgrammerForAppointment(#id)")
    public ResponseEntity<AppointmentResponseDto> approveAppointment(
            @PathVariable Long id,
            @RequestParam(required = false) String responseMessage) {
        return ResponseEntity.ok(appointmentService.approve(id, responseMessage));
    }

    @PutMapping("/{id}/reject")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isProgrammerForAppointment(#id)")
    public ResponseEntity<AppointmentResponseDto> rejectAppointment(
            @PathVariable Long id,
            @RequestParam(required = false) String responseMessage) {
        return ResponseEntity.ok(appointmentService.reject(id, responseMessage));
    }

    @PutMapping("/{id}/complete")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isProgrammerForAppointment(#id)")
    public ResponseEntity<AppointmentResponseDto> completeAppointment(@PathVariable Long id) {
        return ResponseEntity.ok(appointmentService.complete(id));
    }

    @PutMapping("/{id}/cancel")
    @PreAuthorize("hasRole('ADMIN') or @appointmentSecurity.isClientForAppointment(#id) or @appointmentSecurity.isProgrammerForAppointment(#id)")
    public ResponseEntity<AppointmentResponseDto> cancelAppointment(@PathVariable Long id) {
        return ResponseEntity.ok(appointmentService.cancel(id));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteAppointment(@PathVariable Long id) {
        appointmentService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/upcoming")
    public ResponseEntity<List<AppointmentResponseDto>> getUpcomingAppointments() {
        return ResponseEntity.ok(appointmentService.findUpcomingAppointments());
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<AppointmentResponseDto>> getAppointmentsByStatus(
            @PathVariable String status) {
        return ResponseEntity.ok(appointmentService.findByStatus(status));
    }

    @GetMapping("/search")
    public ResponseEntity<Page<AppointmentResponseDto>> searchAppointments(
            @RequestParam(required = false) Long programmerId,
            @RequestParam(required = false) Long clientId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            Pageable pageable) {
        return ResponseEntity.ok(appointmentService.search(
                programmerId, clientId, status, startDate, endDate, pageable));
    }
}
```

## DTOs
### AppointmentRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.dtos;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.time.LocalDateTime;

public class AppointmentRequestDto {
    @NotNull(message = "El ID del programador es obligatorio")
    private Long programmerId;

    @NotNull(message = "El ID del cliente es obligatorio")
    private Long clientId;

    @NotNull(message = "La fecha y hora son obligatorias")
    @Future(message = "La fecha debe ser en el futuro")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    private LocalDateTime dateTime;

    private String comment;

    @Positive(message = "La duración debe ser positiva")
    private Integer durationMinutes;

    private String meetingLink;

    // Getters y Setters
    public Long getProgrammerId() {
        return programmerId;
    }

    public void setProgrammerId(Long programmerId) {
        this.programmerId = programmerId;
    }

    public Long getClientId() {
        return clientId;
    }

    public void setClientId(Long clientId) {
        this.clientId = clientId;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public void setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public Integer getDurationMinutes() {
        return durationMinutes;
    }

    public void setDurationMinutes(Integer durationMinutes) {
        this.durationMinutes = durationMinutes;
    }

    public String getMeetingLink() {
        return meetingLink;
    }

    public void setMeetingLink(String meetingLink) {
        this.meetingLink = meetingLink;
    }
}
```
### AppointmentResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.dtos;

import java.time.LocalDateTime;

public class AppointmentResponseDto {
    private Long id;
    private Long programmerId;
    private String programmerName;
    private String programmerEmail;
    private Long clientId;
    private String clientName;
    private String clientEmail;
    private LocalDateTime dateTime;
    private String comment;
    private String status;
    private String programmerResponse;
    private Integer durationMinutes;
    private String meetingLink;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getProgrammerId() {
        return programmerId;
    }

    public void setProgrammerId(Long programmerId) {
        this.programmerId = programmerId;
    }

    public String getProgrammerName() {
        return programmerName;
    }

    public void setProgrammerName(String programmerName) {
        this.programmerName = programmerName;
    }

    public String getProgrammerEmail() {
        return programmerEmail;
    }

    public void setProgrammerEmail(String programmerEmail) {
        this.programmerEmail = programmerEmail;
    }

    public Long getClientId() {
        return clientId;
    }

    public void setClientId(Long clientId) {
        this.clientId = clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getClientEmail() {
        return clientEmail;
    }

    public void setClientEmail(String clientEmail) {
        this.clientEmail = clientEmail;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public void setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getProgrammerResponse() {
        return programmerResponse;
    }

    public void setProgrammerResponse(String programmerResponse) {
        this.programmerResponse = programmerResponse;
    }

    public Integer getDurationMinutes() {
        return durationMinutes;
    }

    public void setDurationMinutes(Integer durationMinutes) {
        this.durationMinutes = durationMinutes;
    }

    public String getMeetingLink() {
        return meetingLink;
    }

    public void setMeetingLink(String meetingLink) {
        this.meetingLink = meetingLink;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
```
## Models
### AppointmentEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.models;

import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "appointments")
public class AppointmentEntity extends BaseModel {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "programmer_id", nullable = false)
    private UserEntity programmer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private UserEntity client;

    @Column(nullable = false)
    private LocalDateTime dateTime;

    @Column(length = 500)
    private String comment;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private AppointmentStatus status = AppointmentStatus.PENDING;

    @Column(name = "programmer_response", length = 500)
    private String programmerResponse;

    @Column(name = "duration_minutes")
    private Integer durationMinutes = 60;

    @Column(name = "meeting_link", length = 500)
    private String meetingLink;

    // Constructores
    public AppointmentEntity() {
    }

    public AppointmentEntity(UserEntity programmer, UserEntity client, LocalDateTime dateTime) {
        this.programmer = programmer;
        this.client = client;
        this.dateTime = dateTime;
    }

    // Getters y Setters
    public UserEntity getProgrammer() {
        return programmer;
    }

    public void setProgrammer(UserEntity programmer) {
        this.programmer = programmer;
    }

    public UserEntity getClient() {
        return client;
    }

    public void setClient(UserEntity client) {
        this.client = client;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public void setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public AppointmentStatus getStatus() {
        return status;
    }

    public void setStatus(AppointmentStatus status) {
        this.status = status;
    }

    public String getProgrammerResponse() {
        return programmerResponse;
    }

    public void setProgrammerResponse(String programmerResponse) {
        this.programmerResponse = programmerResponse;
    }

    public Integer getDurationMinutes() {
        return durationMinutes;
    }

    public void setDurationMinutes(Integer durationMinutes) {
        this.durationMinutes = durationMinutes;
    }

    public String getMeetingLink() {
        return meetingLink;
    }

    public void setMeetingLink(String meetingLink) {
        this.meetingLink = meetingLink;
    }
}
```
### AppointmentStatus.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.models;

public enum AppointmentStatus {
    PENDING,
    APPROVED,
    REJECTED,
    COMPLETED,
    CANCELLED
}
```
## Repositories
### AppointmentRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.repositories;

import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AppointmentRepository extends JpaRepository<AppointmentEntity, Long> {
        List<AppointmentEntity> findByProgrammerId(Long programmerId);

        Page<AppointmentEntity> findByProgrammerId(Long programmerId, Pageable pageable);

        List<AppointmentEntity> findByClientId(Long clientId);

        Page<AppointmentEntity> findByClientId(Long clientId, Pageable pageable);

        List<AppointmentEntity> findByStatus(AppointmentStatus status);

        Page<AppointmentEntity> findByStatus(AppointmentStatus status, Pageable pageable);

        List<AppointmentEntity> findByDateTimeAfterAndStatusIn(
                        LocalDateTime dateTime, List<AppointmentStatus> statuses);

        boolean existsByProgrammerIdAndDateTimeBetween(
                        Long programmerId, LocalDateTime start, LocalDateTime end);

        @Query("SELECT a FROM AppointmentEntity a WHERE " +
                        "(:programmerId IS NULL OR a.programmer.id = :programmerId) AND " +
                        "(:clientId IS NULL OR a.client.id = :clientId) AND " +
                        "(:status IS NULL OR a.status = :status) AND " +
                        "(:startDate IS NULL OR a.dateTime >= :startDate) AND " +
                        "(:endDate IS NULL OR a.dateTime <= :endDate)")
        Page<AppointmentEntity> search(
                        @Param("programmerId") Long programmerId,
                        @Param("clientId") Long clientId,
                        @Param("status") AppointmentStatus status,
                        @Param("startDate") LocalDateTime startDate,
                        @Param("endDate") LocalDateTime endDate,
                        Pageable pageable);

        List<AppointmentEntity> findByDateTimeBetweenAndStatusIn(
                        @Param("start") LocalDateTime start,
                        @Param("end") LocalDateTime end,
                        @Param("statuses") List<AppointmentStatus> statuses);

}
```
## Services
### AppointmentMapper.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.services;

import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentRequestDto;
import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentResponseDto;
import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import org.springframework.stereotype.Component;

@Component
public class AppointmentMapper {

    public AppointmentResponseDto toDto(AppointmentEntity appointment) {
        AppointmentResponseDto dto = new AppointmentResponseDto();
        dto.setId(appointment.getId());
        dto.setProgrammerId(appointment.getProgrammer().getId());
        dto.setProgrammerName(appointment.getProgrammer().getName());
        dto.setProgrammerEmail(appointment.getProgrammer().getEmail());
        dto.setClientId(appointment.getClient().getId());
        dto.setClientName(appointment.getClient().getName());
        dto.setClientEmail(appointment.getClient().getEmail());
        dto.setDateTime(appointment.getDateTime());
        dto.setComment(appointment.getComment());
        dto.setStatus(appointment.getStatus().name());
        dto.setProgrammerResponse(appointment.getProgrammerResponse());
        dto.setDurationMinutes(appointment.getDurationMinutes());
        dto.setMeetingLink(appointment.getMeetingLink());
        dto.setCreatedAt(appointment.getCreatedAt());
        dto.setUpdatedAt(appointment.getUpdatedAt());
        return dto;
    }

    public AppointmentEntity toEntity(AppointmentRequestDto dto) {
        AppointmentEntity appointment = new AppointmentEntity();
        appointment.setDateTime(dto.getDateTime());
        appointment.setComment(dto.getComment());
        appointment.setDurationMinutes(dto.getDurationMinutes() != null ? dto.getDurationMinutes() : 60);
        appointment.setMeetingLink(dto.getMeetingLink());
        return appointment;
    }

    public void updateEntity(AppointmentRequestDto dto, AppointmentEntity appointment) {
        if (dto.getDateTime() != null) {
            appointment.setDateTime(dto.getDateTime());
        }
        if (dto.getComment() != null) {
            appointment.setComment(dto.getComment());
        }
        if (dto.getDurationMinutes() != null) {
            appointment.setDurationMinutes(dto.getDurationMinutes());
        }
        if (dto.getMeetingLink() != null) {
            appointment.setMeetingLink(dto.getMeetingLink());
        }
    }
}
```
### AppointmentService.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.services;

import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentRequestDto;
import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentResponseDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface AppointmentService {
    Page<AppointmentResponseDto> findAll(Pageable pageable);

    AppointmentResponseDto findById(Long id);

    List<AppointmentResponseDto> findByProgrammerId(Long programmerId);

    List<AppointmentResponseDto> findByClientId(Long clientId);

    AppointmentResponseDto create(AppointmentRequestDto appointmentDto);

    AppointmentResponseDto update(Long id, AppointmentRequestDto appointmentDto);

    AppointmentResponseDto approve(Long id, String responseMessage);

    AppointmentResponseDto reject(Long id, String responseMessage);

    AppointmentResponseDto complete(Long id);

    AppointmentResponseDto cancel(Long id);

    void delete(Long id);

    List<AppointmentResponseDto> findUpcomingAppointments();

    List<AppointmentResponseDto> findByStatus(String status);

    Page<AppointmentResponseDto> search(Long programmerId, Long clientId, String status,
            String startDate, String endDate, Pageable pageable);
}
```
### AppointmentServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.appointments.services;

import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentRequestDto;
import ec.edu.ups.icc.portafolio.modules.appointments.dtos.AppointmentResponseDto;
import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentStatus;
import ec.edu.ups.icc.portafolio.modules.appointments.repositories.AppointmentRepository;
import ec.edu.ups.icc.portafolio.modules.notifications.services.EmailService;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.BadRequestException;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.ConflictException;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AppointmentServiceImpl implements AppointmentService {

    private final AppointmentRepository appointmentRepository;
    private final UserRepository userRepository;
    private final AppointmentMapper appointmentMapper;
    private final EmailService emailService;

    public AppointmentServiceImpl(AppointmentRepository appointmentRepository,
            UserRepository userRepository,
            AppointmentMapper appointmentMapper,
            EmailService emailService) {
        this.appointmentRepository = appointmentRepository;
        this.userRepository = userRepository;
        this.appointmentMapper = appointmentMapper;
        this.emailService = emailService;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AppointmentResponseDto> findAll(Pageable pageable) {
        return appointmentRepository.findAll(pageable)
                .map(appointmentMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public AppointmentResponseDto findById(Long id) {
        return appointmentRepository.findById(id)
                .map(appointmentMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public List<AppointmentResponseDto> findByProgrammerId(Long programmerId) {
        return appointmentRepository.findByProgrammerId(programmerId)
                .stream()
                .map(appointmentMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<AppointmentResponseDto> findByClientId(Long clientId) {
        return appointmentRepository.findByClientId(clientId)
                .stream()
                .map(appointmentMapper::toDto)
                .toList();
    }

    @Override
    @Transactional
    public AppointmentResponseDto create(AppointmentRequestDto appointmentDto) {
        UserEntity programmer = userRepository.findById(appointmentDto.getProgrammerId())
                .orElseThrow(() -> new NotFoundException(
                        "Programador no encontrado con ID: " + appointmentDto.getProgrammerId()));

        UserEntity client = userRepository.findById(appointmentDto.getClientId())
                .orElseThrow(
                        () -> new NotFoundException("Cliente no encontrado con ID: " + appointmentDto.getClientId()));

        LocalDateTime dateTime = appointmentDto.getDateTime();
        if (dateTime.isBefore(LocalDateTime.now())) {
            throw new BadRequestException("La fecha no puede ser en el pasado");
        }

        boolean hasConflict = appointmentRepository.existsByProgrammerIdAndDateTimeBetween(
                appointmentDto.getProgrammerId(),
                dateTime.minusHours(1),
                dateTime.plusHours(1));

        if (hasConflict) {
            throw new ConflictException("El programador ya tiene una cita programada en ese horario");
        }

        AppointmentEntity appointment = appointmentMapper.toEntity(appointmentDto);
        appointment.setProgrammer(programmer);
        appointment.setClient(client);
        appointment.setStatus(AppointmentStatus.PENDING);

        AppointmentEntity saved = appointmentRepository.save(appointment);

        emailService.sendAppointmentNotification(saved);

        return appointmentMapper.toDto(saved);
    }

    @Override
    @Transactional
    public AppointmentResponseDto update(Long id, AppointmentRequestDto appointmentDto) {
        AppointmentEntity appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));

        if (!appointment.getStatus().equals(AppointmentStatus.PENDING)) {
            throw new BadRequestException("Solo se pueden modificar citas en estado PENDING");
        }

        appointmentMapper.updateEntity(appointmentDto, appointment);
        AppointmentEntity updated = appointmentRepository.save(appointment);
        return appointmentMapper.toDto(updated);
    }

    @Override
    @Transactional
    public AppointmentResponseDto approve(Long id, String responseMessage) {
        AppointmentEntity appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));

        if (!appointment.getStatus().equals(AppointmentStatus.PENDING)) {
            throw new BadRequestException("Solo se pueden aprobar citas en estado PENDING");
        }

        appointment.setStatus(AppointmentStatus.APPROVED);
        appointment.setProgrammerResponse(responseMessage);

        AppointmentEntity updated = appointmentRepository.save(appointment);

        emailService.sendAppointmentApproval(updated);

        return appointmentMapper.toDto(updated);
    }

    @Override
    @Transactional
    public AppointmentResponseDto reject(Long id, String responseMessage) {
        AppointmentEntity appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));

        if (!appointment.getStatus().equals(AppointmentStatus.PENDING)) {
            throw new BadRequestException("Solo se pueden rechazar citas en estado PENDING");
        }

        appointment.setStatus(AppointmentStatus.REJECTED);
        appointment.setProgrammerResponse(responseMessage);

        AppointmentEntity updated = appointmentRepository.save(appointment);

        emailService.sendAppointmentRejection(updated);

        return appointmentMapper.toDto(updated);
    }

    @Override
    @Transactional
    public AppointmentResponseDto complete(Long id) {
        AppointmentEntity appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));

        if (!appointment.getStatus().equals(AppointmentStatus.APPROVED)) {
            throw new BadRequestException("Solo se pueden completar citas en estado APPROVED");
        }

        appointment.setStatus(AppointmentStatus.COMPLETED);
        AppointmentEntity updated = appointmentRepository.save(appointment);
        return appointmentMapper.toDto(updated);
    }

    @Override
    @Transactional
    public AppointmentResponseDto cancel(Long id) {
        AppointmentEntity appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + id));

        if (appointment.getStatus().equals(AppointmentStatus.COMPLETED) ||
                appointment.getStatus().equals(AppointmentStatus.CANCELLED)) {
            throw new BadRequestException("No se puede cancelar una cita en estado " + appointment.getStatus());
        }

        appointment.setStatus(AppointmentStatus.CANCELLED);
        AppointmentEntity updated = appointmentRepository.save(appointment);
        return appointmentMapper.toDto(updated);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!appointmentRepository.existsById(id)) {
            throw new NotFoundException("Cita no encontrada con ID: " + id);
        }
        appointmentRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<AppointmentResponseDto> findUpcomingAppointments() {
        return appointmentRepository.findByDateTimeAfterAndStatusIn(
                LocalDateTime.now(),
                List.of(AppointmentStatus.PENDING, AppointmentStatus.APPROVED))
                .stream()
                .map(appointmentMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<AppointmentResponseDto> findByStatus(String status) {
        AppointmentStatus statusEnum = AppointmentStatus.valueOf(status.toUpperCase());
        return appointmentRepository.findByStatus(statusEnum)
                .stream()
                .map(appointmentMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AppointmentResponseDto> search(Long programmerId, Long clientId, String status,
            String startDate, String endDate, Pageable pageable) {
        if (programmerId != null) {
            return appointmentRepository.findByProgrammerId(programmerId, pageable)
                    .map(appointmentMapper::toDto);
        }

        if (clientId != null) {
            return appointmentRepository.findByClientId(clientId, pageable)
                    .map(appointmentMapper::toDto);
        }

        if (status != null) {
            AppointmentStatus statusEnum = AppointmentStatus.valueOf(status.toUpperCase());
            return appointmentRepository.findByStatus(statusEnum, pageable)
                    .map(appointmentMapper::toDto);
        }

        return appointmentRepository.findAll(pageable)
                .map(appointmentMapper::toDto);
    }
}
```

## Autenticación (/modules/auth/)
### AuthController.java
```java
package ec.edu.ups.icc.portafolio.modules.auth.controllers;

import ec.edu.ups.icc.portafolio.modules.auth.dtos.LoginRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.RegisterRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.AuthResponseDto;
import ec.edu.ups.icc.portafolio.modules.auth.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody LoginRequestDto loginRequest) {
        AuthResponseDto response = authService.login(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@Valid @RequestBody RegisterRequestDto registerRequest) {
        AuthResponseDto response = authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
```
### AuthService.java

```java
package ec.edu.ups.icc.portafolio.modules.auth.services;

import ec.edu.ups.icc.portafolio.config.security.JwtUtil;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.LoginRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.RegisterRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.AuthResponseDto;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.RoleRepository;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.ConflictException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Transactional(readOnly = true)
    public AuthResponseDto login(LoginRequestDto loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtil.generateToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toSet());

        return new AuthResponseDto(
                jwt,
                userDetails.getId(),
                userDetails.getName(),
                userDetails.getEmail(),
                roles);
    }

    @Transactional
    public AuthResponseDto register(RegisterRequestDto registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new ConflictException("El email ya está registrado");
        }

        UserEntity user = new UserEntity();
        user.setName(registerRequest.getName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        RoleEntity userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Rol por defecto no encontrado"));

        Set<RoleEntity> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        user = userRepository.save(user);

        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String jwt = jwtUtil.generateTokenFromUserDetails(userDetails);

        Set<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());

        return new AuthResponseDto(
                jwt,
                user.getId(),
                user.getName(),
                user.getEmail(),
                roleNames);
    }
}
```
### AuthResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.auth.dtos;

import java.util.Set;

public class AuthResponseDto {
    private String token;
    private String type = "Bearer";
    private Long userId;
    private String name;
    private String email;
    private Set<String> roles;

    public AuthResponseDto() {
    }

    public AuthResponseDto(String token, Long userId, String name, String email, Set<String> roles) {
        this.token = token;
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.roles = roles;
    }

    // Getters y Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}
```
### LoginRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.auth.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class LoginRequestDto {
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe ser válido")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
    private String password;

    // Getters y Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```
### RegisterRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.auth.dtos;

import jakarta.validation.constraints.*;

public class RegisterRequestDto {
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 150, message = "El nombre debe tener entre 3 y 150 caracteres")
    private String name;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe ser válido")
    @Size(max = 150, message = "El email no puede exceder 150 caracteres")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres")
    private String password;

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```
## Usuarios (/modules/users/)
### UserController.java

```java
package ec.edu.ups.icc.portafolio.modules.users.controllers;

import ec.edu.ups.icc.portafolio.modules.users.dtos.UserRequestDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserResponseDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserUpdateDto;
import ec.edu.ups.icc.portafolio.modules.users.services.UserService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(userService.findAll(pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isSelf(#id)")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.findById(id));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponseDto> createUser(@Valid @RequestBody UserRequestDto userDto) {
        UserResponseDto createdUser = userService.create(userDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isSelf(#id)")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserUpdateDto userDto) {
        return ResponseEntity.ok(userService.update(id, userDto));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isSelf(#id)")
    public ResponseEntity<UserResponseDto> partialUpdateUser(
            @PathVariable Long id,
            @RequestBody UserUpdateDto userDto) {
        return ResponseEntity.ok(userService.partialUpdate(id, userDto));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/programmers")
    public ResponseEntity<List<UserResponseDto>> getProgrammers() {
        return ResponseEntity.ok(userService.findProgrammers());
    }

    @GetMapping("/search")
    public ResponseEntity<Page<UserResponseDto>> searchUsers(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role,
            Pageable pageable) {
        return ResponseEntity.ok(userService.search(name, email, role, pageable));
    }
}
```
### UserService.java
```java
package ec.edu.ups.icc.portafolio.modules.users.services;

import ec.edu.ups.icc.portafolio.modules.users.dtos.UserRequestDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserResponseDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserUpdateDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface UserService {
    Page<UserResponseDto> findAll(Pageable pageable);

    UserResponseDto findById(Long id);

    UserResponseDto create(UserRequestDto userDto);

    UserResponseDto update(Long id, UserUpdateDto userDto);

    UserResponseDto partialUpdate(Long id, UserUpdateDto userDto);

    void delete(Long id);

    List<UserResponseDto> findProgrammers();

    Page<UserResponseDto> search(String name, String email, String role, Pageable pageable);
}
```
### UserServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.users.services;

import ec.edu.ups.icc.portafolio.modules.users.dtos.UserRequestDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserResponseDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserUpdateDto;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.RoleRepository;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.ConflictException;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    public UserServiceImpl(UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            UserMapper userMapper) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponseDto> findAll(Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(userMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto findById(Long id) {
        return userRepository.findById(id)
                .map(userMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));
    }

    @Override
    @Transactional
    public UserResponseDto create(UserRequestDto userDto) {
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new ConflictException("El email ya está registrado");
        }

        UserEntity user = userMapper.toEntity(userDto);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        Set<RoleEntity> roles = new HashSet<>();
        for (String roleName : userDto.getRoles()) {
            RoleName roleEnum = RoleName.valueOf(roleName);
            RoleEntity role = roleRepository.findByName(roleEnum)
                    .orElseThrow(() -> new NotFoundException("Rol no encontrado: " + roleName));
            roles.add(role);
        }
        user.setRoles(roles);

        UserEntity savedUser = userRepository.save(user);
        return userMapper.toDto(savedUser);
    }

    @Override
    @Transactional
    public UserResponseDto update(Long id, UserUpdateDto userDto) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));

        if (userDto.getEmail() != null && !userDto.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(userDto.getEmail())) {
                throw new ConflictException("El email ya está registrado");
            }
            user.setEmail(userDto.getEmail());
        }

        userMapper.updateEntity(userDto, user);

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            Set<RoleEntity> roles = new HashSet<>();
            for (String roleName : userDto.getRoles()) {
                RoleName roleEnum = RoleName.valueOf(roleName);
                RoleEntity role = roleRepository.findByName(roleEnum)
                        .orElseThrow(() -> new NotFoundException("Rol no encontrado: " + roleName));
                roles.add(role);
            }
            user.setRoles(roles);
        }

        UserEntity updatedUser = userRepository.save(user);
        return userMapper.toDto(updatedUser);
    }

    @Override
    @Transactional
    public UserResponseDto partialUpdate(Long id, UserUpdateDto userDto) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));

        userMapper.partialUpdate(userDto, user);

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        UserEntity updatedUser = userRepository.save(user);
        return userMapper.toDto(updatedUser);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!userRepository.existsById(id)) {
            throw new NotFoundException("Usuario no encontrado con ID: " + id);
        }
        userRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponseDto> findProgrammers() {
        RoleEntity programmerRole = roleRepository.findByName(RoleName.ROLE_PROGRAMMER)
                .orElseThrow(() -> new NotFoundException("Rol PROGRAMMER no encontrado"));

        return userRepository.findByRole(programmerRole)
        .stream()
        .map(userMapper::toDto)
        .collect(Collectors.toList());

    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponseDto> search(String name, String email, String role, Pageable pageable) {
        if (role != null) {
            RoleName roleEnum = RoleName.valueOf(role);
            RoleEntity roleEntity = roleRepository.findByName(roleEnum)
                    .orElseThrow(() -> new NotFoundException("Rol no encontrado: " + role));

            return userRepository.findByRole(roleEntity, pageable)
        .map(userMapper::toDto);

        }

        if (name != null && email != null) {
            return userRepository.findByNameContainingIgnoreCaseAndEmailContainingIgnoreCase(name, email, pageable)
                    .map(userMapper::toDto);
        } else if (name != null) {
            return userRepository.findByNameContainingIgnoreCase(name, pageable)
                    .map(userMapper::toDto);
        } else if (email != null) {
            return userRepository.findByEmailContainingIgnoreCase(email, pageable)
                    .map(userMapper::toDto);
        }

        return userRepository.findAll(pageable)
                .map(userMapper::toDto);
    }
}
```
### UserDetailsImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.users.services;

import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {

    private final Long id;
    private final String name;
    private final String email;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String name, String email, String password,
            Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(UserEntity user) {
        Collection<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPassword(),
                authorities);
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```
### UserDetailsServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.users.services;

import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "Usuario no encontrado con email: " + email
                        )
                );

        return UserDetailsImpl.build(user);
    }
}

```
### UserMapper.java
```java
package ec.edu.ups.icc.portafolio.modules.users.services;

import ec.edu.ups.icc.portafolio.modules.users.dtos.UserRequestDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserResponseDto;
import ec.edu.ups.icc.portafolio.modules.users.dtos.UserUpdateDto;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public UserResponseDto toDto(UserEntity user) {
        UserResponseDto dto = new UserResponseDto();
        dto.setId(user.getId());
        dto.setName(user.getName());
        dto.setEmail(user.getEmail());
        dto.setBio(user.getBio());
        dto.setProfilePicture(user.getProfilePicture());
        dto.setGithubUrl(user.getGithubUrl());
        dto.setLinkedinUrl(user.getLinkedinUrl());
        dto.setPhone(user.getPhone());
        dto.setRoles(user.getRoles().stream()
                .map(role -> role.getName().name())
                .toList());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        return dto;
    }

    public UserEntity toEntity(UserRequestDto dto) {
        UserEntity user = new UserEntity();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setBio(dto.getBio());
        user.setProfilePicture(dto.getProfilePicture());
        user.setGithubUrl(dto.getGithubUrl());
        user.setLinkedinUrl(dto.getLinkedinUrl());
        user.setPhone(dto.getPhone());
        return user;
    }

    public void updateEntity(UserUpdateDto dto, UserEntity user) {
        if (dto.getName() != null) {
            user.setName(dto.getName());
        }
        if (dto.getEmail() != null) {
            user.setEmail(dto.getEmail());
        }
        if (dto.getBio() != null) {
            user.setBio(dto.getBio());
        }
        if (dto.getProfilePicture() != null) {
            user.setProfilePicture(dto.getProfilePicture());
        }
        if (dto.getGithubUrl() != null) {
            user.setGithubUrl(dto.getGithubUrl());
        }
        if (dto.getLinkedinUrl() != null) {
            user.setLinkedinUrl(dto.getLinkedinUrl());
        }
        if (dto.getPhone() != null) {
            user.setPhone(dto.getPhone());
        }
    }

    public void partialUpdate(UserUpdateDto dto, UserEntity user) {
        updateEntity(dto, user);
    }
}
```
### UserRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.users.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;

public class UserRequestDto {
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 150, message = "El nombre debe tener entre 3 y 150 caracteres")
    private String name;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe ser válido")
    @Size(max = 150, message = "El email no puede exceder 150 caracteres")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @Size(max = 500, message = "La biografía no puede exceder 500 caracteres")
    private String bio;

    private String profilePicture;
    private String githubUrl;
    private String linkedinUrl;

    @Size(max = 20, message = "El teléfono no puede exceder 20 caracteres")
    private String phone;

    private List<String> roles;

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public String getGithubUrl() {
        return githubUrl;
    }

    public void setGithubUrl(String githubUrl) {
        this.githubUrl = githubUrl;
    }

    public String getLinkedinUrl() {
        return linkedinUrl;
    }

    public void setLinkedinUrl(String linkedinUrl) {
        this.linkedinUrl = linkedinUrl;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
```
### UserResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.users.dtos;

import java.time.LocalDateTime;
import java.util.List;

public class UserResponseDto {
    private Long id;
    private String name;
    private String email;
    private String bio;
    private String profilePicture;
    private String githubUrl;
    private String linkedinUrl;
    private String phone;
    private List<String> roles;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public String getGithubUrl() {
        return githubUrl;
    }

    public void setGithubUrl(String githubUrl) {
        this.githubUrl = githubUrl;
    }

    public String getLinkedinUrl() {
        return linkedinUrl;
    }

    public void setLinkedinUrl(String linkedinUrl) {
        this.linkedinUrl = linkedinUrl;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
```
### UserUpdateDto.java

```java
package ec.edu.ups.icc.portafolio.modules.users.dtos;

import java.util.List;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public class UserUpdateDto {
    @Size(min = 3, max = 150, message = "El nombre debe tener entre 3 y 150 caracteres")
    private String name;

    @Email(message = "El email debe ser válido")
    @Size(max = 150, message = "El email no puede exceder 150 caracteres")
    private String email;

    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @Size(max = 500, message = "La biografía no puede exceder 500 caracteres")
    private String bio;

    private String profilePicture;
    private String githubUrl;
    private String linkedinUrl;

    @Size(max = 20, message = "El teléfono no puede exceder 20 caracteres")
    private String phone;

    private List<String> roles;

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public String getGithubUrl() {
        return githubUrl;
    }

    public void setGithubUrl(String githubUrl) {
        this.githubUrl = githubUrl;
    }

    public String getLinkedinUrl() {
        return linkedinUrl;
    }

    public void setLinkedinUrl(String linkedinUrl) {
        this.linkedinUrl = linkedinUrl;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
```
### RoleEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.users.models;

import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
public class RoleEntity extends BaseModel {

    @Column(nullable = false, unique = true, length = 50)
    @Enumerated(EnumType.STRING)
    private RoleName name;

    @Column(length = 200)
    private String description;

    @ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
    private Set<UserEntity> users = new HashSet<>();

    // Constructores
    public RoleEntity() {
    }

    public RoleEntity(RoleName name) {
        this.name = name;
    }

    public RoleEntity(RoleName name, String description) {
        this.name = name;
        this.description = description;
    }

    // Getters y Setters
    public RoleName getName() {
        return name;
    }

    public void setName(RoleName name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<UserEntity> getUsers() {
        return users;
    }

    public void setUsers(Set<UserEntity> users) {
        this.users = users;
    }
}
```
### RoleName.java

```java
package ec.edu.ups.icc.portafolio.modules.users.models;

public enum RoleName {
    ROLE_ADMIN("Administrador del sistema"),
    ROLE_PROGRAMMER("Programador con portafolio"),
    ROLE_USER("Usuario externo que agenda asesorías");

    private final String description;

    RoleName(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
```
### UserEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.users.models;

import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class UserEntity extends BaseModel {

    @Column(nullable = false, length = 150)
    private String name;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(length = 500)
    private String bio;

    @Column(name = "profile_picture")
    private String profilePicture;

    @Column(name = "github_url")
    private String githubUrl;

    @Column(name = "linkedin_url")
    private String linkedinUrl;

    @Column(name = "phone", length = 20)
    private String phone;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles = new HashSet<>();

    // Constructores
    public UserEntity() {
    }

    public UserEntity(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public String getGithubUrl() {
        return githubUrl;
    }

    public void setGithubUrl(String githubUrl) {
        this.githubUrl = githubUrl;
    }

    public String getLinkedinUrl() {
        return linkedinUrl;
    }

    public void setLinkedinUrl(String linkedinUrl) {
        this.linkedinUrl = linkedinUrl;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public Set<RoleEntity> getRoles() {
        return roles;
    }

    public void setRoles(Set<RoleEntity> roles) {
        this.roles = roles;
    }
}
```
### RoleRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.users.repositories;

import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    Optional<RoleEntity> findByName(RoleName name);

    boolean existsByName(RoleName name);
}
```
### UserRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.users.repositories;

import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmail(String email);

    boolean existsByEmail(String email);

    Page<UserEntity> findByNameContainingIgnoreCase(String name, Pageable pageable);

    Page<UserEntity> findByEmailContainingIgnoreCase(String email, Pageable pageable);

    Page<UserEntity> findByNameContainingIgnoreCaseAndEmailContainingIgnoreCase(
            String name, String email, Pageable pageable);

    List<UserEntity> findByRolesContaining(RoleEntity role);

    Page<UserEntity> findByRolesContaining(RoleEntity role, Pageable pageable);

    @Query("SELECT u FROM UserEntity u JOIN u.roles r WHERE r.name = :roleName")
    Page<UserEntity> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    @Query("SELECT u FROM UserEntity u WHERE u.createdAt > :date")
    List<UserEntity> findByCreatedAtAfter(@Param("date") LocalDateTime date);
}
```
## Portafolios (/modules/portfolios/)
### PortfolioController.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.controllers;

import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioRequestDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioResponseDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.services.PortfolioService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/portfolios")
public class PortfolioController {

    private final PortfolioService portfolioService;

    public PortfolioController(PortfolioService portfolioService) {
        this.portfolioService = portfolioService;
    }

    @GetMapping
    public ResponseEntity<Page<PortfolioResponseDto>> getAllPortfolios(Pageable pageable) {
        return ResponseEntity.ok(portfolioService.findAll(pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PortfolioResponseDto> getPortfolioById(@PathVariable Long id) {
        return ResponseEntity.ok(portfolioService.findById(id));
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<PortfolioResponseDto> getPortfolioByUserId(@PathVariable Long userId) {
        return ResponseEntity.ok(portfolioService.findByUserId(userId));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('PROGRAMMER')")
    public ResponseEntity<PortfolioResponseDto> createPortfolio(
            @Valid @RequestBody PortfolioRequestDto portfolioDto) {
        PortfolioResponseDto createdPortfolio = portfolioService.create(portfolioDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdPortfolio);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @portfolioSecurity.isOwner(#id)")
    public ResponseEntity<PortfolioResponseDto> updatePortfolio(
            @PathVariable Long id,
            @Valid @RequestBody PortfolioRequestDto portfolioDto) {
        return ResponseEntity.ok(portfolioService.update(id, portfolioDto));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @portfolioSecurity.isOwner(#id)")
    public ResponseEntity<Void> deletePortfolio(@PathVariable Long id) {
        portfolioService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/speciality/{speciality}")
    public ResponseEntity<List<PortfolioResponseDto>> getPortfoliosBySpeciality(
            @PathVariable String speciality) {
        return ResponseEntity.ok(portfolioService.findBySpeciality(speciality));
    }

    @GetMapping("/available")
    public ResponseEntity<List<PortfolioResponseDto>> getAvailablePortfolios() {
        return ResponseEntity.ok(portfolioService.findAvailablePortfolios());
    }

    @GetMapping("/search")
    public ResponseEntity<Page<PortfolioResponseDto>> searchPortfolios(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String speciality,
            @RequestParam(required = false) Integer minExperience,
            @RequestParam(required = false) Integer maxExperience,
            Pageable pageable) {
        return ResponseEntity.ok(portfolioService.search(
                name, speciality, minExperience, maxExperience, pageable));
    }
}
```
### PortfolioService.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.services;

import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioRequestDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioResponseDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface PortfolioService {
    Page<PortfolioResponseDto> findAll(Pageable pageable);

    PortfolioResponseDto findById(Long id);

    PortfolioResponseDto findByUserId(Long userId);

    PortfolioResponseDto create(PortfolioRequestDto portfolioDto);

    PortfolioResponseDto update(Long id, PortfolioRequestDto portfolioDto);

    void delete(Long id);

    List<PortfolioResponseDto> findBySpeciality(String speciality);

    List<PortfolioResponseDto> findAvailablePortfolios();

    Page<PortfolioResponseDto> search(String name, String speciality,
            Integer minExperience, Integer maxExperience,
            Pageable pageable);
}
```
### PortfolioServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.services;

import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioRequestDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioResponseDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.PortfolioEntity;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.Speciality;
import ec.edu.ups.icc.portafolio.modules.portfolios.repositories.PortfolioRepository;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.ConflictException;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class PortfolioServiceImpl implements PortfolioService {

    private final PortfolioRepository portfolioRepository;
    private final UserRepository userRepository;
    private final PortfolioMapper portfolioMapper;

    public PortfolioServiceImpl(PortfolioRepository portfolioRepository,
            UserRepository userRepository,
            PortfolioMapper portfolioMapper) {
        this.portfolioRepository = portfolioRepository;
        this.userRepository = userRepository;
        this.portfolioMapper = portfolioMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PortfolioResponseDto> findAll(Pageable pageable) {
        return portfolioRepository.findAll(pageable)
                .map(portfolioMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public PortfolioResponseDto findById(Long id) {
        return portfolioRepository.findById(id)
                .map(portfolioMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Portafolio no encontrado con ID: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public PortfolioResponseDto findByUserId(Long userId) {
        return portfolioRepository.findByUserId(userId)
                .map(portfolioMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Portafolio no encontrado para el usuario ID: " + userId));
    }

    @Override
    @Transactional
    public PortfolioResponseDto create(PortfolioRequestDto portfolioDto) {
        UserEntity user = userRepository.findById(portfolioDto.getUserId())
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + portfolioDto.getUserId()));

        if (portfolioRepository.existsByUserId(portfolioDto.getUserId())) {
            throw new ConflictException("El usuario ya tiene un portafolio registrado");
        }

        PortfolioEntity portfolio = portfolioMapper.toEntity(portfolioDto);
        portfolio.setUser(user);
        portfolio.setIsAvailable(true);

        PortfolioEntity savedPortfolio = portfolioRepository.save(portfolio);
        return portfolioMapper.toDto(savedPortfolio);
    }

    @Override
    @Transactional
    public PortfolioResponseDto update(Long id, PortfolioRequestDto portfolioDto) {
        PortfolioEntity portfolio = portfolioRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Portafolio no encontrado con ID: " + id));

        portfolioMapper.updateEntity(portfolioDto, portfolio);
        PortfolioEntity updatedPortfolio = portfolioRepository.save(portfolio);
        return portfolioMapper.toDto(updatedPortfolio);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!portfolioRepository.existsById(id)) {
            throw new NotFoundException("Portafolio no encontrado con ID: " + id);
        }
        portfolioRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<PortfolioResponseDto> findBySpeciality(String speciality) {
        Speciality specialityEnum = Speciality.valueOf(speciality.toUpperCase());
        return portfolioRepository.findBySpeciality(specialityEnum)
                .stream()
                .map(portfolioMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<PortfolioResponseDto> findAvailablePortfolios() {
        return portfolioRepository.findByIsAvailableTrue()
                .stream()
                .map(portfolioMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PortfolioResponseDto> search(String name, String speciality,
            Integer minExperience, Integer maxExperience,
            Pageable pageable) {
        if (speciality != null) {
            Speciality specialityEnum = Speciality.valueOf(speciality.toUpperCase());
            if (minExperience != null && maxExperience != null) {
                return portfolioRepository.findBySpecialityAndYearsExperienceBetween(
                        specialityEnum, minExperience, maxExperience, pageable)
                        .map(portfolioMapper::toDto);
            } else if (minExperience != null) {
                return portfolioRepository.findBySpecialityAndYearsExperienceGreaterThanEqual(
                        specialityEnum, minExperience, pageable)
                        .map(portfolioMapper::toDto);
            } else if (maxExperience != null) {
                return portfolioRepository.findBySpecialityAndYearsExperienceLessThanEqual(
                        specialityEnum, maxExperience, pageable)
                        .map(portfolioMapper::toDto);
            } else {
                return portfolioRepository.findBySpeciality(specialityEnum, pageable)
                        .map(portfolioMapper::toDto);
            }
        }

        if (name != null) {
            return portfolioRepository.findByUserNameContainingIgnoreCase(name, pageable)
                    .map(portfolioMapper::toDto);
        }

        return portfolioRepository.findAll(pageable)
                .map(portfolioMapper::toDto);
    }
}
```
### PortfolioMapper.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.services;

import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioRequestDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.dtos.PortfolioResponseDto;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.PortfolioEntity;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.Speciality;
import org.springframework.stereotype.Component;

@Component
public class PortfolioMapper {

    public PortfolioResponseDto toDto(PortfolioEntity portfolio) {
        PortfolioResponseDto dto = new PortfolioResponseDto();
        dto.setId(portfolio.getId());
        dto.setUserId(portfolio.getUser().getId());
        dto.setUserName(portfolio.getUser().getName());
        dto.setUserEmail(portfolio.getUser().getEmail());
        dto.setSpeciality(portfolio.getSpeciality().name());
        dto.setYearsExperience(portfolio.getYearsExperience());
        dto.setHourlyRate(portfolio.getHourlyRate());
        dto.setIsAvailable(portfolio.getIsAvailable());
        dto.setCreatedAt(portfolio.getCreatedAt());
        dto.setUpdatedAt(portfolio.getUpdatedAt());
        return dto;
    }

    public PortfolioEntity toEntity(PortfolioRequestDto dto) {
        PortfolioEntity portfolio = new PortfolioEntity();
        portfolio.setSpeciality(Speciality.valueOf(dto.getSpeciality().toUpperCase()));
        portfolio.setYearsExperience(dto.getYearsExperience());
        portfolio.setHourlyRate(dto.getHourlyRate());
        portfolio.setIsAvailable(dto.getIsAvailable() != null ? dto.getIsAvailable() : true);
        return portfolio;
    }

    public void updateEntity(PortfolioRequestDto dto, PortfolioEntity portfolio) {
        if (dto.getSpeciality() != null) {
            portfolio.setSpeciality(Speciality.valueOf(dto.getSpeciality().toUpperCase()));
        }
        if (dto.getYearsExperience() != null) {
            portfolio.setYearsExperience(dto.getYearsExperience());
        }
        if (dto.getHourlyRate() != null) {
            portfolio.setHourlyRate(dto.getHourlyRate());
        }
        if (dto.getIsAvailable() != null) {
            portfolio.setIsAvailable(dto.getIsAvailable());
        }
    }
}
```
### PortfolioRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.dtos;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public class PortfolioRequestDto {
    @NotNull(message = "El ID del usuario es obligatorio")
    private Long userId;

    @NotNull(message = "La especialidad es obligatoria")
    private String speciality;

    @Min(value = 0, message = "Los años de experiencia no pueden ser negativos")
    private Integer yearsExperience;

    @Positive(message = "La tarifa por hora debe ser positiva")
    private Double hourlyRate;

    private Boolean isAvailable;

    // Getters y Setters
    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getSpeciality() {
        return speciality;
    }

    public void setSpeciality(String speciality) {
        this.speciality = speciality;
    }

    public Integer getYearsExperience() {
        return yearsExperience;
    }

    public void setYearsExperience(Integer yearsExperience) {
        this.yearsExperience = yearsExperience;
    }

    public Double getHourlyRate() {
        return hourlyRate;
    }

    public void setHourlyRate(Double hourlyRate) {
        this.hourlyRate = hourlyRate;
    }

    public Boolean getIsAvailable() {
        return isAvailable;
    }

    public void setIsAvailable(Boolean isAvailable) {
        this.isAvailable = isAvailable;
    }
}
```
### PortfolioResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.dtos;

import java.time.LocalDateTime;

public class PortfolioResponseDto {
    private Long id;
    private Long userId;
    private String userName;
    private String userEmail;
    private String speciality;
    private Integer yearsExperience;
    private Double hourlyRate;
    private Boolean isAvailable;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getSpeciality() {
        return speciality;
    }

    public void setSpeciality(String speciality) {
        this.speciality = speciality;
    }

    public Integer getYearsExperience() {
        return yearsExperience;
    }

    public void setYearsExperience(Integer yearsExperience) {
        this.yearsExperience = yearsExperience;
    }

    public Double getHourlyRate() {
        return hourlyRate;
    }

    public void setHourlyRate(Double hourlyRate) {
        this.hourlyRate = hourlyRate;
    }

    public Boolean getIsAvailable() {
        return isAvailable;
    }

    public void setIsAvailable(Boolean isAvailable) {
        this.isAvailable = isAvailable;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
```
### PortfolioEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.models;

import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "portfolios")
public class PortfolioEntity extends BaseModel {

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private UserEntity user;

    @Column(name = "speciality", nullable = false)
    @Enumerated(EnumType.STRING)
    private Speciality speciality;

    @Column(name = "years_experience")
    private Integer yearsExperience;

    @Column(name = "hourly_rate")
    private Double hourlyRate;

    @Column(name = "is_available")
    private Boolean isAvailable = true;

    @OneToMany(mappedBy = "portfolio", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<ProjectEntity> projects = new ArrayList<>();

    // Constructores
    public PortfolioEntity() {
    }

    public PortfolioEntity(UserEntity user, Speciality speciality) {
        this.user = user;
        this.speciality = speciality;
    }

    // Getters y Setters
    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public Speciality getSpeciality() {
        return speciality;
    }

    public void setSpeciality(Speciality speciality) {
        this.speciality = speciality;
    }

    public Integer getYearsExperience() {
        return yearsExperience;
    }

    public void setYearsExperience(Integer yearsExperience) {
        this.yearsExperience = yearsExperience;
    }

    public Double getHourlyRate() {
        return hourlyRate;
    }

    public void setHourlyRate(Double hourlyRate) {
        this.hourlyRate = hourlyRate;
    }

    public Boolean getIsAvailable() {
        return isAvailable;
    }

    public void setIsAvailable(Boolean isAvailable) {
        this.isAvailable = isAvailable;
    }

    public List<ProjectEntity> getProjects() {
        return projects;
    }

    public void setProjects(List<ProjectEntity> projects) {
        this.projects = projects;
    }
}
```
### Speciality.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.models;

public enum Speciality {
    FRONTEND,
    BACKEND,
    FULLSTACK,
    MOBILE,
    DEVOPS,
    DATABASE,
    UI_UX
}
```
### PortfolioRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.portfolios.repositories;

import ec.edu.ups.icc.portafolio.modules.portfolios.models.PortfolioEntity;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.Speciality;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PortfolioRepository extends JpaRepository<PortfolioEntity, Long> {
        Optional<PortfolioEntity> findByUserId(Long userId);

        boolean existsByUserId(Long userId);

        List<PortfolioEntity> findBySpeciality(Speciality speciality);

        Page<PortfolioEntity> findBySpeciality(Speciality speciality, Pageable pageable);

        List<PortfolioEntity> findByIsAvailableTrue();

        @Query("SELECT p FROM PortfolioEntity p WHERE p.user.name LIKE %:name%")
        Page<PortfolioEntity> findByUserNameContainingIgnoreCase(@Param("name") String name, Pageable pageable);

        Page<PortfolioEntity> findBySpecialityAndYearsExperienceBetween(
                        Speciality speciality, Integer minExperience, Integer maxExperience, Pageable pageable);

        Page<PortfolioEntity> findBySpecialityAndYearsExperienceGreaterThanEqual(
                        Speciality speciality, Integer minExperience, Pageable pageable);

        Page<PortfolioEntity> findBySpecialityAndYearsExperienceLessThanEqual(
                        Speciality speciality, Integer maxExperience, Pageable pageable);
}
```
## Proyectos (/modules/projects/)
### ProjectController.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.controllers;

import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectRequestDto;
import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectResponseDto;
import ec.edu.ups.icc.portafolio.modules.projects.services.ProjectService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private final ProjectService projectService;

    public ProjectController(ProjectService projectService) {
        this.projectService = projectService;
    }

    @GetMapping
    public ResponseEntity<Page<ProjectResponseDto>> getAllProjects(Pageable pageable) {
        return ResponseEntity.ok(projectService.findAll(pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProjectResponseDto> getProjectById(@PathVariable Long id) {
        return ResponseEntity.ok(projectService.findById(id));
    }

    @GetMapping("/portfolio/{portfolioId}")
    public ResponseEntity<List<ProjectResponseDto>> getProjectsByPortfolioId(
            @PathVariable Long portfolioId) {
        return ResponseEntity.ok(projectService.findByPortfolioId(portfolioId));
    }

    @GetMapping("/type/{projectType}")
    public ResponseEntity<List<ProjectResponseDto>> getProjectsByType(
            @PathVariable String projectType) {
        return ResponseEntity.ok(projectService.findByProjectType(projectType));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('PROGRAMMER')")
    public ResponseEntity<ProjectResponseDto> createProject(
            @Valid @RequestBody ProjectRequestDto projectDto) {
        ProjectResponseDto createdProject = projectService.create(projectDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdProject);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @projectSecurity.isPortfolioOwner(#id)")
    public ResponseEntity<ProjectResponseDto> updateProject(
            @PathVariable Long id,
            @Valid @RequestBody ProjectRequestDto projectDto) {
        return ResponseEntity.ok(projectService.update(id, projectDto));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @projectSecurity.isPortfolioOwner(#id)")
    public ResponseEntity<Void> deleteProject(@PathVariable Long id) {
        projectService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/search")
    public ResponseEntity<Page<ProjectResponseDto>> searchProjects(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String projectType,
            @RequestParam(required = false) String participationType,
            @RequestParam(required = false) String technology,
            Pageable pageable) {
        return ResponseEntity.ok(projectService.search(
                name, projectType, participationType, technology, pageable));
    }

    @GetMapping("/portfolio/{portfolioId}/count")
    public ResponseEntity<Long> countProjectsByPortfolioId(@PathVariable Long portfolioId) {
        return ResponseEntity.ok(projectService.countByPortfolioId(portfolioId));
    }
}
```
### ProjectService.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.services;

import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectRequestDto;
import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectResponseDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface ProjectService {
    Page<ProjectResponseDto> findAll(Pageable pageable);

    ProjectResponseDto findById(Long id);

    List<ProjectResponseDto> findByPortfolioId(Long portfolioId);

    List<ProjectResponseDto> findByProjectType(String projectType);

    ProjectResponseDto create(ProjectRequestDto projectDto);

    ProjectResponseDto update(Long id, ProjectRequestDto projectDto);

    void delete(Long id);

    Page<ProjectResponseDto> search(String name, String projectType,
            String participationType, String technology,
            Pageable pageable);

    Long countByPortfolioId(Long portfolioId);
}
```
### ProjectServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.services;

import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectRequestDto;
import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectResponseDto;
import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectEntity;
import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectType;
import ec.edu.ups.icc.portafolio.modules.projects.models.ParticipationType;
import ec.edu.ups.icc.portafolio.modules.projects.repositories.ProjectRepository;
import ec.edu.ups.icc.portafolio.modules.portfolios.models.PortfolioEntity;
import ec.edu.ups.icc.portafolio.modules.portfolios.repositories.PortfolioRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ProjectServiceImpl implements ProjectService {

    private final ProjectRepository projectRepository;
    private final PortfolioRepository portfolioRepository;
    private final ProjectMapper projectMapper;

    public ProjectServiceImpl(ProjectRepository projectRepository,
            PortfolioRepository portfolioRepository,
            ProjectMapper projectMapper) {
        this.projectRepository = projectRepository;
        this.portfolioRepository = portfolioRepository;
        this.projectMapper = projectMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ProjectResponseDto> findAll(Pageable pageable) {
        return projectRepository.findAll(pageable)
                .map(projectMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public ProjectResponseDto findById(Long id) {
        return projectRepository.findById(id)
                .map(projectMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Proyecto no encontrado con ID: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProjectResponseDto> findByPortfolioId(Long portfolioId) {
        return projectRepository.findByPortfolioId(portfolioId)
                .stream()
                .map(projectMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProjectResponseDto> findByProjectType(String projectType) {
        ProjectType type = ProjectType.valueOf(projectType.toUpperCase());
        return projectRepository.findByProjectType(type)
                .stream()
                .map(projectMapper::toDto)
                .toList();
    }

    @Override
    @Transactional
    public ProjectResponseDto create(ProjectRequestDto projectDto) {
        PortfolioEntity portfolio = portfolioRepository.findById(projectDto.getPortfolioId())
                .orElseThrow(
                        () -> new NotFoundException("Portafolio no encontrado con ID: " + projectDto.getPortfolioId()));

        ProjectEntity project = projectMapper.toEntity(projectDto);
        project.setPortfolio(portfolio);

        ProjectEntity savedProject = projectRepository.save(project);
        return projectMapper.toDto(savedProject);
    }

    @Override
    @Transactional
    public ProjectResponseDto update(Long id, ProjectRequestDto projectDto) {
        ProjectEntity project = projectRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Proyecto no encontrado con ID: " + id));

        projectMapper.updateEntity(projectDto, project);

        if (projectDto.getPortfolioId() != null) {
            PortfolioEntity portfolio = portfolioRepository.findById(projectDto.getPortfolioId())
                    .orElseThrow(() -> new NotFoundException(
                            "Portafolio no encontrado con ID: " + projectDto.getPortfolioId()));
            project.setPortfolio(portfolio);
        }

        ProjectEntity updatedProject = projectRepository.save(project);
        return projectMapper.toDto(updatedProject);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!projectRepository.existsById(id)) {
            throw new NotFoundException("Proyecto no encontrado con ID: " + id);
        }
        projectRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ProjectResponseDto> search(String name, String projectType,
            String participationType, String technology,
            Pageable pageable) {
        if (name != null) {
            return projectRepository.findByNameContainingIgnoreCase(name, pageable)
                    .map(projectMapper::toDto);
        }

        if (projectType != null) {
            ProjectType type = ProjectType.valueOf(projectType.toUpperCase());
            return projectRepository.findByProjectType(type, pageable)
                    .map(projectMapper::toDto);
        }

        if (participationType != null) {
            ParticipationType participation = ParticipationType.valueOf(participationType.toUpperCase());
            return projectRepository.findByParticipationType(participation, pageable)
                    .map(projectMapper::toDto);
        }

        if (technology != null) {
            return projectRepository.findByTechnologiesContaining(technology, pageable)
                    .map(projectMapper::toDto);
        }

        return projectRepository.findAll(pageable)
                .map(projectMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public Long countByPortfolioId(Long portfolioId) {
        return projectRepository.countByPortfolioId(portfolioId);
    }
}
```
### ProjectMapper.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.services;

import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectRequestDto;
import ec.edu.ups.icc.portafolio.modules.projects.dtos.ProjectResponseDto;
import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectEntity;
import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectType;
import ec.edu.ups.icc.portafolio.modules.projects.models.ParticipationType;
import org.springframework.stereotype.Component;

@Component
public class ProjectMapper {

    public ProjectResponseDto toDto(ProjectEntity project) {
        ProjectResponseDto dto = new ProjectResponseDto();
        dto.setId(project.getId());
        dto.setName(project.getName());
        dto.setDescription(project.getDescription());
        dto.setProjectType(project.getProjectType().name());
        dto.setParticipationType(project.getParticipationType().name());
        dto.setTechnologies(project.getTechnologies());
        dto.setRepositoryUrl(project.getRepositoryUrl());
        dto.setDemoUrl(project.getDemoUrl());
        dto.setImageUrl(project.getImageUrl());
        dto.setPortfolioId(project.getPortfolio().getId());
        dto.setPortfolioName(project.getPortfolio().getUser().getName());
        dto.setCreatedAt(project.getCreatedAt());
        dto.setUpdatedAt(project.getUpdatedAt());
        return dto;
    }

    public ProjectEntity toEntity(ProjectRequestDto dto) {
        ProjectEntity project = new ProjectEntity();
        project.setName(dto.getName());
        project.setDescription(dto.getDescription());
        project.setProjectType(ProjectType.valueOf(dto.getProjectType().toUpperCase()));
        project.setParticipationType(ParticipationType.valueOf(dto.getParticipationType().toUpperCase()));
        project.setTechnologies(dto.getTechnologies());
        project.setRepositoryUrl(dto.getRepositoryUrl());
        project.setDemoUrl(dto.getDemoUrl());
        project.setImageUrl(dto.getImageUrl());
        return project;
    }

    public void updateEntity(ProjectRequestDto dto, ProjectEntity project) {
        if (dto.getName() != null) {
            project.setName(dto.getName());
        }
        if (dto.getDescription() != null) {
            project.setDescription(dto.getDescription());
        }
        if (dto.getProjectType() != null) {
            project.setProjectType(ProjectType.valueOf(dto.getProjectType().toUpperCase()));
        }
        if (dto.getParticipationType() != null) {
            project.setParticipationType(ParticipationType.valueOf(dto.getParticipationType().toUpperCase()));
        }
        if (dto.getTechnologies() != null) {
            project.setTechnologies(dto.getTechnologies());
        }
        if (dto.getRepositoryUrl() != null) {
            project.setRepositoryUrl(dto.getRepositoryUrl());
        }
        if (dto.getDemoUrl() != null) {
            project.setDemoUrl(dto.getDemoUrl());
        }
        if (dto.getImageUrl() != null) {
            project.setImageUrl(dto.getImageUrl());
        }
    }
}
```
### ProjectRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

public class ProjectRequestDto {
    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 200, message = "El nombre no puede exceder 200 caracteres")
    private String name;

    @Size(max = 1000, message = "La descripción no puede exceder 1000 caracteres")
    private String description;

    @NotNull(message = "El tipo de proyecto es obligatorio")
    private String projectType;

    @NotNull(message = "El tipo de participación es obligatorio")
    private String participationType;

    private List<String> technologies;
    private String repositoryUrl;
    private String demoUrl;
    private String imageUrl;

    @NotNull(message = "El ID del portafolio es obligatorio")
    private Long portfolioId;

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProjectType() {
        return projectType;
    }

    public void setProjectType(String projectType) {
        this.projectType = projectType;
    }

    public String getParticipationType() {
        return participationType;
    }

    public void setParticipationType(String participationType) {
        this.participationType = participationType;
    }

    public List<String> getTechnologies() {
        return technologies;
    }

    public void setTechnologies(List<String> technologies) {
        this.technologies = technologies;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

    public String getDemoUrl() {
        return demoUrl;
    }

    public void setDemoUrl(String demoUrl) {
        this.demoUrl = demoUrl;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public Long getPortfolioId() {
        return portfolioId;
    }

    public void setPortfolioId(Long portfolioId) {
        this.portfolioId = portfolioId;
    }
}
```
### ProjectResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.dtos;

import java.time.LocalDateTime;
import java.util.List;

public class ProjectResponseDto {
    private Long id;
    private String name;
    private String description;
    private String projectType;
    private String participationType;
    private List<String> technologies;
    private String repositoryUrl;
    private String demoUrl;
    private String imageUrl;
    private Long portfolioId;
    private String portfolioName;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProjectType() {
        return projectType;
    }

    public void setProjectType(String projectType) {
        this.projectType = projectType;
    }

    public String getParticipationType() {
        return participationType;
    }

    public void setParticipationType(String participationType) {
        this.participationType = participationType;
    }

    public List<String> getTechnologies() {
        return technologies;
    }

    public void setTechnologies(List<String> technologies) {
        this.technologies = technologies;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

    public String getDemoUrl() {
        return demoUrl;
    }

    public void setDemoUrl(String demoUrl) {
        this.demoUrl = demoUrl;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public Long getPortfolioId() {
        return portfolioId;
    }

    public void setPortfolioId(Long portfolioId) {
        this.portfolioId = portfolioId;
    }

    public String getPortfolioName() {
        return portfolioName;
    }

    public void setPortfolioName(String portfolioName) {
        this.portfolioName = portfolioName;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
```
### ProjectEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.models;

import ec.edu.ups.icc.portafolio.modules.portfolios.models.PortfolioEntity;
import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "projects")
public class ProjectEntity extends BaseModel {

    @Column(nullable = false, length = 200)
    private String name;

    @Column(length = 1000)
    private String description;

    @Column(name = "project_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ProjectType projectType;

    @Column(name = "participation_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ParticipationType participationType;

    @ElementCollection
    @CollectionTable(name = "project_technologies", joinColumns = @JoinColumn(name = "project_id"))
    @Column(name = "technology")
    private List<String> technologies = new ArrayList<>();

    @Column(name = "repository_url")
    private String repositoryUrl;

    @Column(name = "demo_url")
    private String demoUrl;

    @Column(name = "image_url")
    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "portfolio_id", nullable = false)
    private PortfolioEntity portfolio;

    // Constructores
    public ProjectEntity() {
    }

    public ProjectEntity(String name, String description, ProjectType projectType,
            ParticipationType participationType) {
        this.name = name;
        this.description = description;
        this.projectType = projectType;
        this.participationType = participationType;
    }

    // Getters y Setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public ProjectType getProjectType() {
        return projectType;
    }

    public void setProjectType(ProjectType projectType) {
        this.projectType = projectType;
    }

    public ParticipationType getParticipationType() {
        return participationType;
    }

    public void setParticipationType(ParticipationType participationType) {
        this.participationType = participationType;
    }

    public List<String> getTechnologies() {
        return technologies;
    }

    public void setTechnologies(List<String> technologies) {
        this.technologies = technologies;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

    public String getDemoUrl() {
        return demoUrl;
    }

    public void setDemoUrl(String demoUrl) {
        this.demoUrl = demoUrl;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public PortfolioEntity getPortfolio() {
        return portfolio;
    }

    public void setPortfolio(PortfolioEntity portfolio) {
        this.portfolio = portfolio;
    }
}
```
### ProjectType.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.models;

public enum ProjectType {
    ACADEMICO,
    LABORAL,
    PERSONAL
}
```
### ParticipationType.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.models;

public enum ParticipationType {
    FRONTEND,
    BACKEND,
    DATABASE,
    FULLSTACK,
    DEVOPS
}
```
### ProjectRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.projects.repositories;

import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectEntity;
import ec.edu.ups.icc.portafolio.modules.projects.models.ProjectType;
import ec.edu.ups.icc.portafolio.modules.projects.models.ParticipationType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProjectRepository extends JpaRepository<ProjectEntity, Long> {
    List<ProjectEntity> findByPortfolioId(Long portfolioId);

    List<ProjectEntity> findByProjectType(ProjectType projectType);

    Page<ProjectEntity> findByProjectType(ProjectType projectType, Pageable pageable);

    Page<ProjectEntity> findByParticipationType(ParticipationType participationType, Pageable pageable);

    Page<ProjectEntity> findByNameContainingIgnoreCase(String name, Pageable pageable);

    @Query("SELECT p FROM ProjectEntity p WHERE :technology MEMBER OF p.technologies")
    Page<ProjectEntity> findByTechnologiesContaining(@Param("technology") String technology, Pageable pageable);

    Long countByPortfolioId(Long portfolioId);
}
```
## Disponibilidad (/modules/availabilities/)
### AvailabilityController.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.controllers;

import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityRequestDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityResponseDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.services.AvailabilityService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/availabilities")
public class AvailabilityController {

    private final AvailabilityService availabilityService;

    public AvailabilityController(AvailabilityService availabilityService) {
        this.availabilityService = availabilityService;
    }

    @GetMapping("/programmer/{programmerId}")
    public ResponseEntity<List<AvailabilityResponseDto>> getAvailabilitiesByProgrammer(
            @PathVariable Long programmerId) {
        return ResponseEntity.ok(availabilityService.findByProgrammerId(programmerId));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('PROGRAMMER')")
    public ResponseEntity<AvailabilityResponseDto> createAvailability(
            @Valid @RequestBody AvailabilityRequestDto availabilityDto) {
        AvailabilityResponseDto created = availabilityService.create(availabilityDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @availabilitySecurity.isOwner(#id)")
    public ResponseEntity<AvailabilityResponseDto> updateAvailability(
            @PathVariable Long id,
            @Valid @RequestBody AvailabilityRequestDto availabilityDto) {
        return ResponseEntity.ok(availabilityService.update(id, availabilityDto));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @availabilitySecurity.isOwner(#id)")
    public ResponseEntity<Void> deleteAvailability(@PathVariable Long id) {
        availabilityService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/programmer/{programmerId}/available")
    public ResponseEntity<List<AvailabilityResponseDto>> getAvailableSlots(
            @PathVariable Long programmerId) {
        return ResponseEntity.ok(availabilityService.findActiveByProgrammerId(programmerId));
    }

    @PatchMapping("/{id}/toggle")
    @PreAuthorize("hasRole('ADMIN') or @availabilitySecurity.isOwner(#id)")
    public ResponseEntity<AvailabilityResponseDto> toggleAvailability(
            @PathVariable Long id) {
        return ResponseEntity.ok(availabilityService.toggleStatus(id));
    }
}
```
### AvailabilityService.java
```java
package ec.edu.ups.icc.portafolio.modules.availabilities.services;

import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityRequestDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityResponseDto;

import java.util.List;

public interface AvailabilityService {
    List<AvailabilityResponseDto> findByProgrammerId(Long programmerId);

    List<AvailabilityResponseDto> findActiveByProgrammerId(Long programmerId);

    AvailabilityResponseDto create(AvailabilityRequestDto availabilityDto);

    AvailabilityResponseDto update(Long id, AvailabilityRequestDto availabilityDto);

    void delete(Long id);

    AvailabilityResponseDto toggleStatus(Long id);
}
```
### AvailabilityServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.services;

import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityRequestDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityResponseDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.models.AvailabilityEntity;
import ec.edu.ups.icc.portafolio.modules.availabilities.repositories.AvailabilityRepository;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AvailabilityServiceImpl implements AvailabilityService {

    private final AvailabilityRepository availabilityRepository;
    private final UserRepository userRepository;
    private final AvailabilityMapper availabilityMapper;

    public AvailabilityServiceImpl(AvailabilityRepository availabilityRepository,
            UserRepository userRepository,
            AvailabilityMapper availabilityMapper) {
        this.availabilityRepository = availabilityRepository;
        this.userRepository = userRepository;
        this.availabilityMapper = availabilityMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public List<AvailabilityResponseDto> findByProgrammerId(Long programmerId) {
        return availabilityRepository.findByProgrammerId(programmerId)
                .stream()
                .map(availabilityMapper::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<AvailabilityResponseDto> findActiveByProgrammerId(Long programmerId) {
        return availabilityRepository.findByProgrammerIdAndIsActiveTrue(programmerId)
                .stream()
                .map(availabilityMapper::toDto)
                .toList();
    }

    @Override
    @Transactional
    public AvailabilityResponseDto create(AvailabilityRequestDto availabilityDto) {
        UserEntity programmer = userRepository.findById(availabilityDto.getProgrammerId())
                .orElseThrow(() -> new NotFoundException(
                        "Programador no encontrado con ID: " + availabilityDto.getProgrammerId()));

        AvailabilityEntity availability = availabilityMapper.toEntity(availabilityDto);
        availability.setProgrammer(programmer);
        availability.setIsActive(true);

        AvailabilityEntity saved = availabilityRepository.save(availability);
        return availabilityMapper.toDto(saved);
    }

    @Override
    @Transactional
    public AvailabilityResponseDto update(Long id, AvailabilityRequestDto availabilityDto) {
        AvailabilityEntity availability = availabilityRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Disponibilidad no encontrada con ID: " + id));

        availabilityMapper.updateEntity(availabilityDto, availability);
        AvailabilityEntity updated = availabilityRepository.save(availability);
        return availabilityMapper.toDto(updated);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!availabilityRepository.existsById(id)) {
            throw new NotFoundException("Disponibilidad no encontrada con ID: " + id);
        }
        availabilityRepository.deleteById(id);
    }

    @Override
    @Transactional
    public AvailabilityResponseDto toggleStatus(Long id) {
        AvailabilityEntity availability = availabilityRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Disponibilidad no encontrada con ID: " + id));

        availability.setIsActive(!availability.getIsActive());
        AvailabilityEntity updated = availabilityRepository.save(availability);
        return availabilityMapper.toDto(updated);
    }
}
```
### AvailabilityMapper.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.services;

import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityRequestDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.dtos.AvailabilityResponseDto;
import ec.edu.ups.icc.portafolio.modules.availabilities.models.AvailabilityEntity;
import ec.edu.ups.icc.portafolio.modules.availabilities.models.DayOfWeek;
import ec.edu.ups.icc.portafolio.modules.availabilities.models.Modality;
import org.springframework.stereotype.Component;

@Component
public class AvailabilityMapper {

    public AvailabilityResponseDto toDto(AvailabilityEntity availability) {
        AvailabilityResponseDto dto = new AvailabilityResponseDto();
        dto.setId(availability.getId());
        dto.setProgrammerId(availability.getProgrammer().getId());
        dto.setProgrammerName(availability.getProgrammer().getName());
        dto.setDayOfWeek(availability.getDayOfWeek().name());
        dto.setStartTime(availability.getStartTime());
        dto.setEndTime(availability.getEndTime());
        dto.setModality(availability.getModality().name());
        dto.setIsActive(availability.getIsActive());
        dto.setCreatedAt(availability.getCreatedAt());
        dto.setUpdatedAt(availability.getUpdatedAt());
        return dto;
    }

    public AvailabilityEntity toEntity(AvailabilityRequestDto dto) {
        AvailabilityEntity availability = new AvailabilityEntity();
        availability.setDayOfWeek(DayOfWeek.valueOf(dto.getDayOfWeek().toUpperCase()));
        availability.setStartTime(dto.getStartTime());
        availability.setEndTime(dto.getEndTime());
        availability.setModality(Modality.valueOf(dto.getModality().toUpperCase()));
        availability.setIsActive(dto.getIsActive() != null ? dto.getIsActive() : true);
        return availability;
    }

    public void updateEntity(AvailabilityRequestDto dto, AvailabilityEntity availability) {
        if (dto.getDayOfWeek() != null) {
            availability.setDayOfWeek(DayOfWeek.valueOf(dto.getDayOfWeek().toUpperCase()));
        }
        if (dto.getStartTime() != null) {
            availability.setStartTime(dto.getStartTime());
        }
        if (dto.getEndTime() != null) {
            availability.setEndTime(dto.getEndTime());
        }
        if (dto.getModality() != null) {
            availability.setModality(Modality.valueOf(dto.getModality().toUpperCase()));
        }
        if (dto.getIsActive() != null) {
            availability.setIsActive(dto.getIsActive());
        }
    }
}
```
### AvailabilityRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.dtos;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.NotNull;
import java.time.LocalTime;

public class AvailabilityRequestDto {
    @NotNull(message = "El ID del programador es obligatorio")
    private Long programmerId;

    @NotNull(message = "El día de la semana es obligatorio")
    private String dayOfWeek;

    @NotNull(message = "La hora de inicio es obligatoria")
    @JsonFormat(pattern = "HH:mm")
    private LocalTime startTime;

    @NotNull(message = "La hora de fin es obligatoria")
    @JsonFormat(pattern = "HH:mm")
    private LocalTime endTime;

    @NotNull(message = "La modalidad es obligatoria")
    private String modality;

    private Boolean isActive;

    // Getters y Setters
    public Long getProgrammerId() {
        return programmerId;
    }

    public void setProgrammerId(Long programmerId) {
        this.programmerId = programmerId;
    }

    public String getDayOfWeek() {
        return dayOfWeek;
    }

    public void setDayOfWeek(String dayOfWeek) {
        this.dayOfWeek = dayOfWeek;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }

    public String getModality() {
        return modality;
    }

    public void setModality(String modality) {
        this.modality = modality;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }
}
```
### AvailabilityResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.dtos;

import java.time.LocalDateTime;
import java.time.LocalTime;

public class AvailabilityResponseDto {
    private Long id;
    private Long programmerId;
    private String programmerName;
    private String dayOfWeek;
    private LocalTime startTime;
    private LocalTime endTime;
    private String modality;
    private Boolean isActive;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getProgrammerId() {
        return programmerId;
    }

    public void setProgrammerId(Long programmerId) {
        this.programmerId = programmerId;
    }

    public String getProgrammerName() {
        return programmerName;
    }

    public void setProgrammerName(String programmerName) {
        this.programmerName = programmerName;
    }

    public String getDayOfWeek() {
        return dayOfWeek;
    }

    public void setDayOfWeek(String dayOfWeek) {
        this.dayOfWeek = dayOfWeek;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }

    public String getModality() {
        return modality;
    }

    public void setModality(String modality) {
        this.modality = modality;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
```
### AvailabilityEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.models;

import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;
import java.time.LocalTime;

@Entity
@Table(name = "availabilities")
public class AvailabilityEntity extends BaseModel {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "programmer_id", nullable = false)
    private UserEntity programmer;

    @Column(name = "day_of_week", nullable = false)
    @Enumerated(EnumType.STRING)
    private DayOfWeek dayOfWeek;

    @Column(name = "start_time", nullable = false)
    private LocalTime startTime;

    @Column(name = "end_time", nullable = false)
    private LocalTime endTime;

    @Column(name = "modality", nullable = false)
    @Enumerated(EnumType.STRING)
    private Modality modality;

    @Column(name = "is_active")
    private Boolean isActive = true;

    // Constructores
    public AvailabilityEntity() {
    }

    public AvailabilityEntity(UserEntity programmer, DayOfWeek dayOfWeek,
            LocalTime startTime, LocalTime endTime, Modality modality) {
        this.programmer = programmer;
        this.dayOfWeek = dayOfWeek;
        this.startTime = startTime;
        this.endTime = endTime;
        this.modality = modality;
    }

    // Getters y Setters
    public UserEntity getProgrammer() {
        return programmer;
    }

    public void setProgrammer(UserEntity programmer) {
        this.programmer = programmer;
    }

    public DayOfWeek getDayOfWeek() {
        return dayOfWeek;
    }

    public void setDayOfWeek(DayOfWeek dayOfWeek) {
        this.dayOfWeek = dayOfWeek;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }

    public Modality getModality() {
        return modality;
    }

    public void setModality(Modality modality) {
        this.modality = modality;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }
}
```
### DayOfWeek.java
```java
package ec.edu.ups.icc.portafolio.modules.availabilities.models;

public enum DayOfWeek {
    MONDAY,
    TUESDAY,
    WEDNESDAY,
    THURSDAY,
    FRIDAY,
    SATURDAY,
    SUNDAY
}
```
### Modality.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.models;

public enum Modality {
    PRESENCIAL,
    VIRTUAL,
    HIBRIDO
}
```
### AvailabilityRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.availabilities.repositories;

import ec.edu.ups.icc.portafolio.modules.availabilities.models.AvailabilityEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AvailabilityRepository extends JpaRepository<AvailabilityEntity, Long> {
    List<AvailabilityEntity> findByProgrammerId(Long programmerId);

    List<AvailabilityEntity> findByProgrammerIdAndIsActiveTrue(Long programmerId);

    List<AvailabilityEntity> findByProgrammerIdAndDayOfWeekAndIsActiveTrue(
            Long programmerId, String dayOfWeek);
}
```

## Notificaciones (/modules/notifications/)
### NotificationController.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.controllers;

import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationRequestDto;
import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationResponseDto;
import ec.edu.ups.icc.portafolio.modules.notifications.services.NotificationService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<NotificationResponseDto>> getAllNotifications(Pageable pageable) {
        return ResponseEntity.ok(notificationService.findAll(pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isOwner(#id)")
    public ResponseEntity<NotificationResponseDto> getNotificationById(@PathVariable Long id) {
        return ResponseEntity.ok(notificationService.findById(id));
    }

    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isUserOwner(#userId)")
    public ResponseEntity<List<NotificationResponseDto>> getNotificationsByUserId(
            @PathVariable Long userId) {
        return ResponseEntity.ok(notificationService.findByUserId(userId));
    }

    @GetMapping("/user/{userId}/unread")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isUserOwner(#userId)")
    public ResponseEntity<List<NotificationResponseDto>> getUnreadNotificationsByUserId(
            @PathVariable Long userId) {
        return ResponseEntity.ok(notificationService.findUnreadByUserId(userId));
    }

    @GetMapping("/user/{userId}/count-unread")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isUserOwner(#userId)")
    public ResponseEntity<Long> countUnreadNotifications(@PathVariable Long userId) {
        return ResponseEntity.ok(notificationService.countUnreadByUserId(userId));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<NotificationResponseDto> createNotification(
            @Valid @RequestBody NotificationRequestDto notificationDto) {
        NotificationResponseDto created = notificationService.create(notificationDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PostMapping("/send-appointment-notification")
    public ResponseEntity<Void> sendAppointmentNotification(
            @RequestParam Long appointmentId) {
        notificationService.sendAppointmentNotification(appointmentId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/send-reminder")
    public ResponseEntity<Void> sendReminderNotification(
            @RequestParam Long appointmentId) {
        notificationService.sendAppointmentReminder(appointmentId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/{id}/mark-as-read")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isOwner(#id)")
    public ResponseEntity<NotificationResponseDto> markAsRead(@PathVariable Long id) {
        return ResponseEntity.ok(notificationService.markAsRead(id));
    }

    @PutMapping("/user/{userId}/mark-all-as-read")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isUserOwner(#userId)")
    public ResponseEntity<Void> markAllAsRead(@PathVariable Long userId) {
        notificationService.markAllAsRead(userId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteNotification(@PathVariable Long id) {
        notificationService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @notificationSecurity.isUserOwner(#userId)")
    public ResponseEntity<Void> deleteAllByUserId(@PathVariable Long userId) {
        notificationService.deleteAllByUserId(userId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/types")
    public ResponseEntity<List<String>> getNotificationTypes() {
        return ResponseEntity.ok(notificationService.getNotificationTypes());
    }
}
```
### NotificationService.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.services;

import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationRequestDto;
import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationResponseDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface NotificationService {

    // CRUD operations
    Page<NotificationResponseDto> findAll(Pageable pageable);

    NotificationResponseDto findById(Long id);

    List<NotificationResponseDto> findByUserId(Long userId);

    List<NotificationResponseDto> findUnreadByUserId(Long userId);

    NotificationResponseDto create(NotificationRequestDto notificationDto);

    NotificationResponseDto createForUser(Long userId, String title, String message, String type, String metadata);

    NotificationResponseDto update(Long id, NotificationRequestDto notificationDto);

    void delete(Long id);

    void deleteAllByUserId(Long userId);

    // Status operations
    NotificationResponseDto markAsRead(Long id);

    void markAllAsRead(Long userId);

    long countUnreadByUserId(Long userId);

    // Business logic
    void sendAppointmentNotification(Long appointmentId);

    void sendAppointmentReminder(Long appointmentId);

    void sendAppointmentStatusChange(Long appointmentId, String newStatus, String message);

    // Utility
    List<String> getNotificationTypes();

    void sendWelcomeNotification(Long userId);

    void sendPasswordChangedNotification(Long userId);

    void sendProfileUpdatedNotification(Long userId);
}
```
### NotificationServiceImpl.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.services;

import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import ec.edu.ups.icc.portafolio.modules.appointments.repositories.AppointmentRepository;
import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationRequestDto;
import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationResponseDto;
import ec.edu.ups.icc.portafolio.modules.notifications.models.NotificationEntity;
import ec.edu.ups.icc.portafolio.modules.notifications.models.NotificationType;
import ec.edu.ups.icc.portafolio.modules.notifications.repositories.NotificationRepository;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.NotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class NotificationServiceImpl implements NotificationService {

    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;
    private final AppointmentRepository appointmentRepository;
    private final NotificationMapper notificationMapper;
    private final ObjectMapper objectMapper;

    public NotificationServiceImpl(NotificationRepository notificationRepository,
            UserRepository userRepository,
            AppointmentRepository appointmentRepository,
            NotificationMapper notificationMapper,
            ObjectMapper objectMapper) {
        this.notificationRepository = notificationRepository;
        this.userRepository = userRepository;
        this.appointmentRepository = appointmentRepository;
        this.notificationMapper = notificationMapper;
        this.objectMapper = objectMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<NotificationResponseDto> findAll(Pageable pageable) {
        return notificationRepository.findAll(pageable)
                .map(notificationMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public NotificationResponseDto findById(Long id) {
        return notificationRepository.findById(id)
                .map(notificationMapper::toDto)
                .orElseThrow(() -> new NotFoundException("Notificación no encontrada con ID: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public List<NotificationResponseDto> findByUserId(Long userId) {
        return notificationRepository.findByUserId(userId)
                .stream()
                .map(notificationMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<NotificationResponseDto> findUnreadByUserId(Long userId) {
        return notificationRepository.findByUserIdAndReadFalse(userId)
                .stream()
                .map(notificationMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public NotificationResponseDto create(NotificationRequestDto notificationDto) {
        UserEntity user = userRepository.findById(notificationDto.getUserId())
                .orElseThrow(
                        () -> new NotFoundException("Usuario no encontrado con ID: " + notificationDto.getUserId()));

        NotificationEntity notification = notificationMapper.toEntity(notificationDto);
        notification.setUser(user);

        NotificationEntity saved = notificationRepository.save(notification);

        // Enviar correo si es una notificación importante
        if (shouldSendEmail(notification.getType())) {
            sendNotificationEmail(user, notification);
        }

        return notificationMapper.toDto(saved);
    }

    @Override
    @Transactional
    public NotificationResponseDto createForUser(Long userId, String title, String message,
            String type, String metadata) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + userId));

        NotificationEntity notification = new NotificationEntity();
        notification.setUser(user);
        notification.setTitle(title);
        notification.setMessage(message);
        notification.setType(type);
        notification.setMetadata(metadata);
        notification.setRead(false);

        NotificationEntity saved = notificationRepository.save(notification);
        return notificationMapper.toDto(saved);
    }

    @Override
    @Transactional
    public NotificationResponseDto update(Long id, NotificationRequestDto notificationDto) {
        NotificationEntity notification = notificationRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Notificación no encontrada con ID: " + id));

        notificationMapper.updateEntity(notificationDto, notification);
        NotificationEntity updated = notificationRepository.save(notification);
        return notificationMapper.toDto(updated);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!notificationRepository.existsById(id)) {
            throw new NotFoundException("Notificación no encontrada con ID: " + id);
        }
        notificationRepository.deleteById(id);
    }

    @Override
    @Transactional
    public void deleteAllByUserId(Long userId) {
        notificationRepository.deleteByUserId(userId);
    }

    @Override
    @Transactional
    public NotificationResponseDto markAsRead(Long id) {
        NotificationEntity notification = notificationRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Notificación no encontrada con ID: " + id));

        notification.setRead(true);
        NotificationEntity updated = notificationRepository.save(notification);
        return notificationMapper.toDto(updated);
    }

    @Override
    @Transactional
    public void markAllAsRead(Long userId) {
        notificationRepository.markAllAsReadByUserId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public long countUnreadByUserId(Long userId) {
        return notificationRepository.countByUserIdAndReadFalse(userId);
    }

    @Override
    @Transactional
    public void sendAppointmentNotification(Long appointmentId) {
        AppointmentEntity appointment = appointmentRepository.findById(appointmentId)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + appointmentId));

        // Notificación para el cliente
        String clientTitle = "Solicitud de Asesoría Enviada";
        String clientMessage = String.format(
                "Tu solicitud de asesoría con %s ha sido enviada. Fecha: %s",
                appointment.getProgrammer().getName(),
                formatDateTime(appointment.getDateTime()));

        createForUser(
                appointment.getClient().getId(),
                clientTitle,
                clientMessage,
                NotificationType.APPOINTMENT_CREATED.name(),
                createAppointmentMetadata(appointment));

        // Notificación para el programador
        String programmerTitle = "Nueva Solicitud de Asesoría";
        String programmerMessage = String.format(
                "%s ha solicitado una asesoría. Fecha: %s",
                appointment.getClient().getName(),
                formatDateTime(appointment.getDateTime()));

        createForUser(
                appointment.getProgrammer().getId(),
                programmerTitle,
                programmerMessage,
                NotificationType.APPOINTMENT_CREATED.name(),
                createAppointmentMetadata(appointment));
    }

    @Override
    @Transactional
    public void sendAppointmentReminder(Long appointmentId) {
        AppointmentEntity appointment = appointmentRepository.findById(appointmentId)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + appointmentId));

        String title = "Recordatorio de Asesoría";
        String message = String.format(
                "Recordatorio: Tienes una asesoría programada para %s con %s",
                formatDateTime(appointment.getDateTime()),
                appointment.getClient().getName());

        // Notificación para el programador
        createForUser(
                appointment.getProgrammer().getId(),
                title,
                message,
                NotificationType.APPOINTMENT_REMINDER.name(),
                createAppointmentMetadata(appointment));

        // Notificación para el cliente
        String clientMessage = String.format(
                "Recordatorio: Tienes una asesoría programada para %s con %s",
                formatDateTime(appointment.getDateTime()),
                appointment.getProgrammer().getName());

        createForUser(
                appointment.getClient().getId(),
                title,
                clientMessage,
                NotificationType.APPOINTMENT_REMINDER.name(),
                createAppointmentMetadata(appointment));
    }

    @Override
    @Transactional
    public void sendAppointmentStatusChange(Long appointmentId, String newStatus, String message) {
        AppointmentEntity appointment = appointmentRepository.findById(appointmentId)
                .orElseThrow(() -> new NotFoundException("Cita no encontrada con ID: " + appointmentId));

        String title = "Estado de Asesoría Actualizado";
        String notificationMessage = String.format(
                "Tu asesoría con %s ha sido %s. %s",
                appointment.getProgrammer().getName(),
                newStatus.toLowerCase(),
                message != null ? "Motivo: " + message : "");

        createForUser(
                appointment.getClient().getId(),
                title,
                notificationMessage,
                getNotificationTypeForStatus(newStatus),
                createAppointmentMetadata(appointment));
    }

    @Override
    public List<String> getNotificationTypes() {
        return List.of(
                NotificationType.APPOINTMENT_CREATED.name(),
                NotificationType.APPOINTMENT_APPROVED.name(),
                NotificationType.APPOINTMENT_REJECTED.name(),
                NotificationType.APPOINTMENT_REMINDER.name(),
                NotificationType.APPOINTMENT_CANCELLED.name(),
                NotificationType.APPOINTMENT_COMPLETED.name(),
                NotificationType.SYSTEM_NOTIFICATION.name(),
                NotificationType.WELCOME_MESSAGE.name(),
                NotificationType.PROFILE_UPDATED.name(),
                NotificationType.PASSWORD_CHANGED.name());
    }

    @Override
    @Transactional
    public void sendWelcomeNotification(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + userId));

        String title = "¡Bienvenido a Portafolio Administrable!";
        String message = String.format(
                "Hola %s, gracias por registrarte en nuestra plataforma. " +
                        "Ahora puedes explorar portafolios de programadores y agendar asesorías.",
                user.getName());

        createForUser(
                userId,
                title,
                message,
                NotificationType.WELCOME_MESSAGE.name(),
                null);
    }

    @Override
    @Transactional
    public void sendPasswordChangedNotification(Long userId) {
        String title = "Contraseña Actualizada";
        String message = "Tu contraseña ha sido cambiada exitosamente. " +
                "Si no realizaste este cambio, por favor contacta con soporte.";

        createForUser(
                userId,
                title,
                message,
                NotificationType.PASSWORD_CHANGED.name(),
                null);
    }

    @Override
    @Transactional
    public void sendProfileUpdatedNotification(Long userId) {
        String title = "Perfil Actualizado";
        String message = "Tu perfil ha sido actualizado exitosamente.";

        createForUser(
                userId,
                title,
                message,
                NotificationType.PROFILE_UPDATED.name(),
                null);
    }

    // ============== MÉTODOS PRIVADOS ==============

    private boolean shouldSendEmail(String type) {
        return List.of(
                NotificationType.APPOINTMENT_CREATED.name(),
                NotificationType.APPOINTMENT_APPROVED.name(),
                NotificationType.APPOINTMENT_REJECTED.name(),
                NotificationType.APPOINTMENT_REMINDER.name()).contains(type);
    }

    private void sendNotificationEmail(UserEntity user, NotificationEntity notification) {
        try {
            // Aquí podrías implementar el envío de correo
            // emailService.sendNotificationEmail(user.getEmail(), notification.getTitle(),
            // notification.getMessage());
        } catch (Exception e) {
            // Log the error but don't throw exception
            System.err.println("Error enviando correo de notificación: " + e.getMessage());
        }
    }

    private String formatDateTime(LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
        return dateTime.format(formatter);
    }

    private String createAppointmentMetadata(AppointmentEntity appointment) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("appointmentId", appointment.getId());
            metadata.put("programmerId", appointment.getProgrammer().getId());
            metadata.put("programmerName", appointment.getProgrammer().getName());
            metadata.put("clientId", appointment.getClient().getId());
            metadata.put("clientName", appointment.getClient().getName());
            metadata.put("dateTime", appointment.getDateTime().toString());
            metadata.put("status", appointment.getStatus().name());

            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String getNotificationTypeForStatus(String status) {
        return switch (status.toUpperCase()) {
            case "APPROVED" -> NotificationType.APPOINTMENT_APPROVED.name();
            case "REJECTED" -> NotificationType.APPOINTMENT_REJECTED.name();
            case "CANCELLED" -> NotificationType.APPOINTMENT_CANCELLED.name();
            case "COMPLETED" -> NotificationType.APPOINTMENT_COMPLETED.name();
            default -> NotificationType.SYSTEM_NOTIFICATION.name();
        };
    }
}
```
### NotificationMapper.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.services;

import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationRequestDto;
import ec.edu.ups.icc.portafolio.modules.notifications.dtos.NotificationResponseDto;
import ec.edu.ups.icc.portafolio.modules.notifications.models.NotificationEntity;
import org.springframework.stereotype.Component;

@Component
public class NotificationMapper {

    public NotificationResponseDto toDto(NotificationEntity notification) {
        NotificationResponseDto dto = new NotificationResponseDto();
        dto.setId(notification.getId());
        dto.setUserId(notification.getUser().getId());
        dto.setUserName(notification.getUser().getName());
        dto.setUserEmail(notification.getUser().getEmail());
        dto.setTitle(notification.getTitle());
        dto.setMessage(notification.getMessage());
        dto.setType(notification.getType());
        dto.setRead(notification.isRead());
        dto.setActionUrl(notification.getActionUrl());
        dto.setMetadata(notification.getMetadata());
        dto.setCreatedAt(notification.getCreatedAt());
        dto.setReadAt(notification.getReadAt());
        return dto;
    }

    public NotificationEntity toEntity(NotificationRequestDto dto) {
        NotificationEntity entity = new NotificationEntity();
        entity.setTitle(dto.getTitle());
        entity.setMessage(dto.getMessage());
        entity.setType(dto.getType());
        entity.setActionUrl(dto.getActionUrl());
        entity.setMetadata(dto.getMetadata());
        entity.setRead(false);
        return entity;
    }

    public void updateEntity(NotificationRequestDto dto, NotificationEntity entity) {
        if (dto.getTitle() != null) {
            entity.setTitle(dto.getTitle());
        }
        if (dto.getMessage() != null) {
            entity.setMessage(dto.getMessage());
        }
        if (dto.getType() != null) {
            entity.setType(dto.getType());
        }
        if (dto.getActionUrl() != null) {
            entity.setActionUrl(dto.getActionUrl());
        }
        if (dto.getMetadata() != null) {
            entity.setMetadata(dto.getMetadata());
        }
    }
}
```
### EmailService.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.services;

import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    public EmailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    @Async
    public void sendAppointmentNotification(AppointmentEntity appointment) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(appointment.getClient().getEmail());
            helper.setSubject("Solicitud de Asesoría Enviada");

            Map<String, Object> variables = new HashMap<>();
            variables.put("appointment", appointment);
            variables.put("client", appointment.getClient());
            variables.put("programmer", appointment.getProgrammer());

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("appointment-notification", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de notificación enviado a: {}", appointment.getClient().getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de notificación: {}", e.getMessage());
        }
    }

    @Async
    public void sendAppointmentReminder(AppointmentEntity appointment) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(appointment.getClient().getEmail());
            helper.setSubject("Recordatorio de Asesoría");

            Map<String, Object> variables = new HashMap<>();
            variables.put("appointment", appointment);
            variables.put("programmer", appointment.getProgrammer());
            variables.put("dateTime", formatDateTime(appointment.getDateTime()));

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("appointment-reminder", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de recordatorio enviado a: {}", appointment.getClient().getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de recordatorio: {}", e.getMessage());
        }
    }

    @Async
    public void sendDailySchedule(UserEntity programmer, List<AppointmentEntity> appointments) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(programmer.getEmail());
            helper.setSubject("Horario Diario - " + LocalDate.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy")));

            Map<String, Object> variables = new HashMap<>();
            variables.put("programmer", programmer);
            variables.put("appointments", appointments);
            variables.put("today", LocalDate.now());

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("daily-schedule", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Horario diario enviado a programador: {}", programmer.getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando horario diario: {}", e.getMessage());
        }
    }

    @Async
    public void sendAppointmentApproval(AppointmentEntity appointment) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(appointment.getClient().getEmail());
            helper.setSubject("Asesoría Aprobada");

            Map<String, Object> variables = new HashMap<>();
            variables.put("appointment", appointment);
            variables.put("programmer", appointment.getProgrammer());
            variables.put("response", appointment.getProgrammerResponse());

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("appointment-approved", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de aprobación enviado a: {}", appointment.getClient().getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de aprobación: {}", e.getMessage());
        }
    }

    @Async
    public void sendAppointmentRejection(AppointmentEntity appointment) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(appointment.getClient().getEmail());
            helper.setSubject("Asesoría Rechazada");

            Map<String, Object> variables = new HashMap<>();
            variables.put("appointment", appointment);
            variables.put("programmer", appointment.getProgrammer());
            variables.put("response", appointment.getProgrammerResponse());

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("appointment-rejected", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de rechazo enviado a: {}", appointment.getClient().getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de rechazo: {}", e.getMessage());
        }
    }

    @Async
    public void sendWelcomeEmail(UserEntity user) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(user.getEmail());
            helper.setSubject("¡Bienvenido a Portafolio Administrable!");

            Map<String, Object> variables = new HashMap<>();
            variables.put("user", user);

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("welcome-email", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de bienvenida enviado a: {}", user.getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de bienvenida: {}", e.getMessage());
        }
    }

    @Async
    public void sendPasswordResetEmail(UserEntity user, String resetToken) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(user.getEmail());
            helper.setSubject("Restablecer Contraseña");

            Map<String, Object> variables = new HashMap<>();
            variables.put("user", user);
            variables.put("resetToken", resetToken);
            variables.put("resetUrl", "http://localhost:4200/reset-password?token=" + resetToken);

            Context context = new Context();
            context.setVariables(variables);

            String htmlContent = templateEngine.process("password-reset", context);

            helper.setText(htmlContent, true);
            mailSender.send(message);

            logger.info("📧 Email de restablecimiento enviado a: {}", user.getEmail());

        } catch (MessagingException e) {
            logger.error("❌ Error enviando email de restablecimiento: {}", e.getMessage());
        }
    }

    private String formatDateTime(java.time.LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
        return dateTime.format(formatter);
    }
}
```
### NotificationScheduler.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.services;

import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentEntity;
import ec.edu.ups.icc.portafolio.modules.appointments.models.AppointmentStatus;
import ec.edu.ups.icc.portafolio.modules.appointments.repositories.AppointmentRepository;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class NotificationScheduler {

    private static final Logger logger = LoggerFactory.getLogger(NotificationScheduler.class);

    private final AppointmentRepository appointmentRepository;
    private final UserRepository userRepository;
    private final NotificationService notificationService;
    private final EmailService emailService;

    public NotificationScheduler(AppointmentRepository appointmentRepository,
            UserRepository userRepository,
            NotificationService notificationService,
            EmailService emailService) {
        this.appointmentRepository = appointmentRepository;
        this.userRepository = userRepository;
        this.notificationService = notificationService;
        this.emailService = emailService;
    }

    /**
     * Envía recordatorios de asesorías 1 hora antes
     */
    @Scheduled(cron = "0 0 * * * *") // Cada hora
    @Transactional
    public void sendAppointmentReminders() {
        logger.info("🔔 Ejecutando: Recordatorios de asesorías");

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime reminderTime = now.plusHours(1);

        List<AppointmentEntity> appointments = getAppointmentsForReminder(reminderTime);

        logger.info("📅 Asesorías para recordatorio: {}", appointments.size());

        for (AppointmentEntity appointment : appointments) {
            try {
                // 1. Crear notificación en la aplicación
                notificationService.sendAppointmentReminder(appointment.getId());

                // 2. Enviar email
                emailService.sendAppointmentReminder(appointment);

                logger.info("✅ Recordatorio enviado para asesoría ID: {}", appointment.getId());

            } catch (Exception e) {
                logger.error("❌ Error en asesoría ID {}: {}", appointment.getId(), e.getMessage());
            }
        }
    }

    /**
     * Envía horario diario a programadores
     */
    @Scheduled(cron = "0 0 9 * * *") // 9 AM diario
    @Transactional(readOnly = true)
    public void sendDailyScheduleToProgrammers() {
        logger.info("📅 Ejecutando: Horario diario para programadores");

        LocalDateTime todayStart = LocalDateTime.now().toLocalDate().atStartOfDay();
        LocalDateTime todayEnd = todayStart.plusDays(1);

        List<AppointmentEntity> todayAppointments = appointmentRepository
                .findByDateTimeBetweenAndStatusIn(
                        todayStart,
                        todayEnd,
                        List.of(AppointmentStatus.APPROVED));

        // Agrupar por programador
        var appointmentsByProgrammer = todayAppointments.stream()
                .collect(Collectors.groupingBy(AppointmentEntity::getProgrammer));

        appointmentsByProgrammer.forEach((programmer, appointments) -> {
            try {
                emailService.sendDailySchedule(programmer, appointments);
                logger.info("📧 Horario enviado a: {}", programmer.getEmail());
            } catch (Exception e) {
                logger.error("❌ Error para {}: {}", programmer.getEmail(), e.getMessage());
            }
        });
    }

    /**
     * Envía emails de bienvenida a nuevos usuarios (ejecución manual desde
     * servicio)
     */
    public void sendWelcomeEmailsToNewUsers() {
        logger.info("👋 Ejecutando: Emails de bienvenida");

        // Obtener usuarios creados en las últimas 24 horas sin email de bienvenida
        LocalDateTime yesterday = LocalDateTime.now().minusDays(1);

        List<UserEntity> newUsers = userRepository.findByCreatedAtAfter(yesterday);

        for (UserEntity user : newUsers) {
            try {
                emailService.sendWelcomeEmail(user);
                logger.info("👋 Bienvenida enviada a: {}", user.getEmail());
            } catch (Exception e) {
                logger.error("❌ Error para {}: {}", user.getEmail(), e.getMessage());
            }
        }
    }

    /**
     * Limpia notificaciones antiguas
     */
    @Scheduled(cron = "0 0 2 * * *") // 2 AM diario
    @Transactional
    public void cleanupOldData() {
        logger.info("🧹 Ejecutando: Limpieza de datos antiguos");

        LocalDateTime ninetyDaysAgo = LocalDateTime.now().minusDays(90);

        // Aquí implementarías la lógica de limpieza
        // Por ejemplo: notificationRepository.deleteByCreatedAtBefore(ninetyDaysAgo);

        logger.info("✅ Limpieza completada");
    }

    // ============== MÉTODOS PRIVADOS ==============

    private List<AppointmentEntity> getAppointmentsForReminder(LocalDateTime reminderTime) {
        return appointmentRepository.findByDateTimeBetweenAndStatusIn(
                reminderTime.minusMinutes(5),
                reminderTime.plusMinutes(5),
                List.of(AppointmentStatus.APPROVED));
    }
}
```
### NotificationSecurity.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.security;

import ec.edu.ups.icc.portafolio.modules.notifications.repositories.NotificationRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("notificationSecurity")
public class NotificationSecurity {

    private final NotificationRepository notificationRepository;

    public NotificationSecurity(NotificationRepository notificationRepository) {
        this.notificationRepository = notificationRepository;
    }

    public boolean isOwner(Long notificationId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long userId = userDetails.getId();

        return notificationRepository.findById(notificationId)
                .map(notification -> notification.getUser().getId().equals(userId))
                .orElse(false);
    }

    public boolean isUserOwner(Long targetUserId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetailsImpl)) {
            return false;
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) principal;
        Long currentUserId = userDetails.getId();

        // El usuario puede ver sus propias notificaciones
        // O si es ADMIN puede ver cualquier notificación
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        return currentUserId.equals(targetUserId) || isAdmin;
    }
}
```
### NotificationRequestDto.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class NotificationRequestDto {

    @NotNull(message = "El ID del usuario es obligatorio")
    private Long userId;

    @NotBlank(message = "El título es obligatorio")
    @Size(max = 200, message = "El título no puede exceder 200 caracteres")
    private String title;

    @NotBlank(message = "El mensaje es obligatorio")
    @Size(max = 1000, message = "El mensaje no puede exceder 1000 caracteres")
    private String message;

    @NotBlank(message = "El tipo de notificación es obligatorio")
    private String type;

    private String actionUrl;
    private String metadata;

    // Getters y Setters
    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getActionUrl() {
        return actionUrl;
    }

    public void setActionUrl(String actionUrl) {
        this.actionUrl = actionUrl;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }
}
```
### NotificationResponseDto.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.dtos;

import java.time.LocalDateTime;

public class NotificationResponseDto {

    private Long id;
    private Long userId;
    private String userName;
    private String userEmail;
    private String title;
    private String message;
    private String type;
    private boolean read;
    private String actionUrl;
    private String metadata;
    private LocalDateTime createdAt;
    private LocalDateTime readAt;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isRead() {
        return read;
    }

    public void setRead(boolean read) {
        this.read = read;
    }

    public String getActionUrl() {
        return actionUrl;
    }

    public void setActionUrl(String actionUrl) {
        this.actionUrl = actionUrl;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getReadAt() {
        return readAt;
    }

    public void setReadAt(LocalDateTime readAt) {
        this.readAt = readAt;
    }
}
```
### NotificationEntity.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.models;

import java.time.LocalDateTime;

import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.shared.entities.BaseModel;
import jakarta.persistence.*;

@Entity
@Table(name = "notifications")
public class NotificationEntity extends BaseModel {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, length = 1000)
    private String message;

    @Column(nullable = false, length = 50)
    private String type; // APPOINTMENT_CREATED, APPOINTMENT_APPROVED, APPOINTMENT_REJECTED,
                         // APPOINTMENT_REMINDER, SYSTEM

    @Column(name = "is_read")
    private boolean read = false;

    @Column(name = "action_url", length = 500)
    private String actionUrl;

    @Column(columnDefinition = "TEXT")
    private String metadata; // JSON con datos adicionales

    @Column(name = "read_at")
    private LocalDateTime readAt;

    // Constructores
    public NotificationEntity() {
    }

    public NotificationEntity(UserEntity user, String title, String message, String type) {
        this.user = user;
        this.title = title;
        this.message = message;
        this.type = type;
    }

    // Getters y Setters
    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isRead() {
        return read;
    }

    public void setRead(boolean read) {
        this.read = read;
        if (read && this.readAt == null) {
            this.readAt = LocalDateTime.now();
        }
    }

    public String getActionUrl() {
        return actionUrl;
    }

    public void setActionUrl(String actionUrl) {
        this.actionUrl = actionUrl;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public LocalDateTime getReadAt() {
        return readAt;
    }

    public void setReadAt(LocalDateTime readAt) {
        this.readAt = readAt;
    }
}
```
### NotificationType.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.models;

public enum NotificationType {
    APPOINTMENT_CREATED("Nueva solicitud de asesoría"),
    APPOINTMENT_APPROVED("Asesoría aprobada"),
    APPOINTMENT_REJECTED("Asesoría rechazada"),
    APPOINTMENT_REMINDER("Recordatorio de asesoría"),
    APPOINTMENT_CANCELLED("Asesoría cancelada"),
    APPOINTMENT_COMPLETED("Asesoría completada"),
    SYSTEM_NOTIFICATION("Notificación del sistema"),
    WELCOME_MESSAGE("Mensaje de bienvenida"),
    PROFILE_UPDATED("Perfil actualizado"),
    PASSWORD_CHANGED("Contraseña cambiada");

    private final String description;

    NotificationType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static NotificationType fromString(String type) {
        for (NotificationType notificationType : NotificationType.values()) {
            if (notificationType.name().equalsIgnoreCase(type)) {
                return notificationType;
            }
        }
        return SYSTEM_NOTIFICATION;
    }
}
```
### NotificationRepository.java

```java
package ec.edu.ups.icc.portafolio.modules.notifications.repositories;

import ec.edu.ups.icc.portafolio.modules.notifications.models.NotificationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface NotificationRepository extends JpaRepository<NotificationEntity, Long> {

    List<NotificationEntity> findByUserId(Long userId);

    Page<NotificationEntity> findByUserId(Long userId, Pageable pageable);

    List<NotificationEntity> findByUserIdAndReadFalse(Long userId);

    long countByUserIdAndReadFalse(Long userId);

    List<NotificationEntity> findByType(String type);

    List<NotificationEntity> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    List<NotificationEntity> findByUserIdAndType(Long userId, String type);

    @Modifying
    @Query("UPDATE NotificationEntity n SET n.read = true, n.readAt = CURRENT_TIMESTAMP WHERE n.user.id = :userId AND n.read = false")
    int markAllAsReadByUserId(@Param("userId") Long userId);

    @Modifying
    void deleteByUserId(Long userId);

    @Query("SELECT n FROM NotificationEntity n WHERE n.user.id = :userId ORDER BY n.createdAt DESC")
    List<NotificationEntity> findLatestByUserId(@Param("userId") Long userId, Pageable pageable);

    @Query("SELECT n.type, COUNT(n) FROM NotificationEntity n WHERE n.createdAt >= :since GROUP BY n.type")
    List<Object[]> countByTypeSince(@Param("since") LocalDateTime since);
}
```
## Clase Principal
### PortafolioApplication.java

```java
package ec.edu.ups.icc.portafolio;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PortafolioApplication {

	public static void main(String[] args) {
		SpringApplication.run(PortafolioApplication.class, args);
	}

}

```
## 📄 Archivos de configuración
### application.yaml

```java
spring:
    application:
        name: portfolio
    datasource:
        url: jdbc:postgresql://localhost:5432/devdb
        username: ups
        password: ups123
    jpa:
        hibernate:
            ddl-auto: create-drop
        show-sql: true
        properties:
            hibernate:
                format_sql: true
                dialect: org.hibernate.dialect.PostgreSQLDialect

# ====== JWT CONFIGURATION (OBLIGATORIO) ======
jwt:
    secret: "portfolioDevSecretKey2024ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    expiration: 86400000    # 24 horas en milisegundos
    refresh-expiration: 604800000  # 7 días
    issuer: "portfolio-ups"
    header: "Authorization"
    prefix: "Bearer "
# =============================================

server:
    port: 8080
```
## Tu configuración aquí
### build.gradle.kts
```java
plugins {
	java
	id("org.springframework.boot") version "4.0.2"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "ec.edu.ups.icc"
version = "0.0.1-SNAPSHOT"
description = "Demo project for Spring Boot"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

repositories {
	mavenCentral()
}

dependencies {
// Spring Boot Starters
    implementation ("org.springframework.boot:spring-boot-starter-web")
    implementation ("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation ("org.springframework.boot:spring-boot-starter-security")
    implementation ("org.springframework.boot:spring-boot-starter-validation")
    implementation ("org.springframework.boot:spring-boot-starter-mail")
    implementation ("org.springframework.boot:spring-boot-starter-thymeleaf")
    
    // Database
    runtimeOnly ("org.postgresql:postgresql")
    
    // JWT
    implementation ("io.jsonwebtoken:jjwt-api:0.12.3")
    runtimeOnly ("io.jsonwebtoken:jjwt-impl:0.12.3")
    runtimeOnly ("io.jsonwebtoken:jjwt-jackson:0.12.3")
    
    // Jackson for Java 8+ dates
    implementation ("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    
    // Utilities
    compileOnly ("org.projectlombok:lombok")
    annotationProcessor ("org.projectlombok:lombok")
    
    // Testing
    testImplementation ("org.springframework.boot:spring-boot-starter-test")
    testImplementation ("org.springframework.security:spring-security-test")
    
    // Swagger/OpenAPI
    implementation ("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0")
    
    // PDF Generation
    implementation ("com.itextpdf:itext7-core:7.2.5")
    
    // Excel Generation
    implementation ("org.apache.poi:poi-ooxml:5.2.3")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
```

