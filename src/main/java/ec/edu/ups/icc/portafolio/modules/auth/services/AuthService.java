package ec.edu.ups.icc.portafolio.modules.auth.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import ec.edu.ups.icc.portafolio.config.security.JwtUtil;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.LoginRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.RegisterRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.AuthResponseDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.GoogleAuthRequestDto;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleEntity;
import ec.edu.ups.icc.portafolio.modules.users.models.RoleName;
import ec.edu.ups.icc.portafolio.modules.users.models.UserEntity;
import ec.edu.ups.icc.portafolio.modules.users.repositories.RoleRepository;
import ec.edu.ups.icc.portafolio.modules.users.repositories.UserRepository;
import ec.edu.ups.icc.portafolio.modules.users.services.UserDetailsImpl;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.AuthenticationException;
import ec.edu.ups.icc.portafolio.shared.exceptions.domain.ConflictException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
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
    private final GoogleIdTokenVerifier verifier;

    public AuthService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String googleClientId) {

        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;

        this.verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                JacksonFactory.getDefaultInstance()) // Usar JacksonFactory en lugar de GsonFactory
                .setAudience(Collections.singletonList(googleClientId))
                .build();
    }

    // ✨ NUEVO método para Google
    @Transactional
    public AuthResponseDto loginWithGoogle(GoogleAuthRequestDto googleRequest) {
        try {
            // 1. Verificar token con Google
            GoogleIdToken idToken = verifier.verify(googleRequest.getIdToken());
            if (idToken == null) {
                throw new AuthenticationException("Token de Google inválido");
            }

            // 2. Obtener información del usuario
            GoogleIdToken.Payload payload = idToken.getPayload();

            String googleId = payload.getSubject();
            String email = payload.getEmail();
            String name = (String) payload.get("name");
            String pictureUrl = (String) payload.get("picture");

            // 3. Buscar o crear usuario
            UserEntity user = userRepository.findByEmail(email)
                    .orElseGet(() -> createUserFromGoogle(googleId, email, name, pictureUrl));

            // 4. Generar JWT
            UserDetailsImpl userDetails = UserDetailsImpl.build(user);
            String jwt = jwtUtil.generateTokenFromUserDetails(userDetails);

            // 5. Retornar respuesta
            Set<String> roles = user.getRoles().stream()
                    .map(role -> role.getName().name())
                    .collect(Collectors.toSet());

            return new AuthResponseDto(
                    jwt,
                    user.getId(),
                    user.getName(),
                    user.getEmail(),
                    roles);

        } catch (GeneralSecurityException | IOException e) {
            throw new AuthenticationException("Error validando token de Google: " + e.getMessage());
        }
    }

    private UserEntity createUserFromGoogle(String googleId, String email, String name, String pictureUrl) {
        // Buscar rol USER por defecto
        RoleEntity userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Rol USER no encontrado"));

        // Crear nuevo usuario
        UserEntity user = new UserEntity();
        user.setName(name != null ? name : email.split("@")[0]);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(googleId + System.currentTimeMillis()));
        user.setProfilePicture(pictureUrl);

        // Asignar rol USER
        Set<RoleEntity> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        return userRepository.save(user);
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