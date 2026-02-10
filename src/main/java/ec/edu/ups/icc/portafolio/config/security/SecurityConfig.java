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

                config.setAllowedOriginPatterns(List.of(
                                "http://localhost:4200"));

                config.setAllowedMethods(List.of(
                                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

                config.setAllowedHeaders(List.of("*"));
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
                                                .requestMatchers(HttpMethod.GET, "/api/portfolios/speciality/*")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/portfolios/available")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/portfolios/search").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/portfolios/user/{userId}")
                                                .authenticated()

                                                // Projects (públicos para explorar)
                                                .requestMatchers(HttpMethod.GET, "/api/projects").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/portfolios/*").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/projects/portfolio/*")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/projects/type/{projectType}")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/projects/search").permitAll()
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/projects/portfolio/{portfolioId}/count")
                                                .authenticated()

                                                // Availabilities (públicos para explorar)
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/availabilities/programmer/{programmerId}")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/availabilities/programmer/{programmerId}/available")
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
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/appointments/programmer/{programmerId}")
                                                .hasRole("ADMIN")
                                                .requestMatchers(HttpMethod.GET, "/api/appointments/client/{clientId}")
                                                .hasRole("ADMIN")

                                                // Availabilities - ADMIN gestiona cualquier disponibilidad
                                                .requestMatchers(HttpMethod.POST, "/api/availabilities")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/availabilities/{id}")
                                                .hasRole("ADMIN")
                                                .requestMatchers(HttpMethod.DELETE, "/api/availabilities/{id}")
                                                .hasRole("ADMIN")

                                                // Notifications - ADMIN panel de control
                                                .requestMatchers(HttpMethod.GET, "/api/notifications").hasRole("ADMIN")
                                                .requestMatchers(HttpMethod.POST, "/api/notifications").hasRole("ADMIN")
                                                .requestMatchers(HttpMethod.DELETE, "/api/notifications/{id}")
                                                .hasRole("ADMIN")
                                                .requestMatchers(HttpMethod.DELETE, "/api/notifications/user/{userId}")
                                                .hasRole("ADMIN")

                                                // ======== PROGRAMMER ENDPOINTS ========
                                                // Portfolios - PROGRAMMER gestiona solo el suyo
                                                .requestMatchers(HttpMethod.POST, "/api/portfolios")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/portfolios/{id}")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.DELETE, "/api/portfolios/{id}")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")

                                                // Projects - PROGRAMMER gestiona solo sus proyectos
                                                .requestMatchers(HttpMethod.POST, "/api/projects")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/projects/{id}")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.DELETE, "/api/projects/{id}")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")

                                                // Appointments - PROGRAMMER gestiona sus citas
                                                .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                                                .hasAnyRole("ADMIN", "PROGRAMMER")

                                                // ======== USER ENDPOINTS ========
                                                // Appointments - USER crea y gestiona sus citas
                                                .requestMatchers(HttpMethod.POST, "/api/appointments")
                                                .hasAnyRole("USER", "ADMIN", "PROGRAMMER")
                                                .requestMatchers(HttpMethod.PUT, "/api/appointments/{id}/*")
                                                .hasAnyRole("USER", "ADMIN", "PROGRAMMER")

                                                // Users - Cada usuario gestiona su perfil
                                                .requestMatchers(HttpMethod.GET, "/api/users/{id}").authenticated()
                                                .requestMatchers(HttpMethod.PUT, "/api/users/{id}").authenticated()
                                                .requestMatchers(HttpMethod.PATCH, "/api/users/{id}").authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/users/programmers").permitAll()

                                                // Notifications - Cada usuario gestiona sus notificaciones
                                                .requestMatchers(HttpMethod.GET, "/api/notifications/user/{userId}")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/notifications/user/{userId}/unread")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.GET,
                                                                "/api/notifications/user/{userId}/count-unread")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.PUT, "/api/notifications/*/mark-as-read")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.PUT,
                                                                "/api/notifications/user/{userId}/mark-all-as-read")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/notifications/types")
                                                .hasRole("ADMIN")

                                                // ======== ENDPOINTS COMPARTIDOS ========
                                                .requestMatchers(HttpMethod.GET, "/api/appointments/upcoming")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/appointments/status/**")
                                                .authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/appointments/search")
                                                .authenticated()

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