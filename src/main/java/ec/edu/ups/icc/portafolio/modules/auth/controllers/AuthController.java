package ec.edu.ups.icc.portafolio.modules.auth.controllers;

import ec.edu.ups.icc.portafolio.modules.auth.dtos.LoginRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.RegisterRequestDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.AuthResponseDto;
import ec.edu.ups.icc.portafolio.modules.auth.dtos.GoogleAuthRequestDto;
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

    // ✨ NUEVO endpoint para Google
    @PostMapping("/google")
    public ResponseEntity<AuthResponseDto> loginWithGoogle(@Valid @RequestBody GoogleAuthRequestDto googleRequest) {
        AuthResponseDto response = authService.loginWithGoogle(googleRequest);
        return ResponseEntity.ok(response);
    }
}