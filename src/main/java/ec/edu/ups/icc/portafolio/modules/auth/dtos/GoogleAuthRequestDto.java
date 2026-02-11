package ec.edu.ups.icc.portafolio.modules.auth.dtos;

import jakarta.validation.constraints.NotBlank;

public class GoogleAuthRequestDto {
    
    @NotBlank(message = "El token de Google es obligatorio")
    private String idToken;
    
    public GoogleAuthRequestDto() {}
    
    public GoogleAuthRequestDto(String idToken) {
        this.idToken = idToken;
    }
    
    public String getIdToken() {
        return idToken;
    }
    
    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }
}