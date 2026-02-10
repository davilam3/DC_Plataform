![logo ups](./public/assets/upslogo.png)

<div style="display: flex; align-items: center; gap: 16px;"> <img src="./public/assets/logo.jpg" width="80" alt="D&S Logo"> <h1 style="margin:0; padding:0;">Proyecto Portafolio D&S | Dev Studio</h1> </div>


**Asignatura:** Programación y Plataformas Web

**Tema:** Proyecto Portafolio Angular

---
#### Autores

**Diana Avila** 
📧 davilam3@est.ups.edu.ec 
💻 GitHub: [Diana Avila](https://github.com/davilam3)

**Sebastian Cabrera**
📧 ccabreram1@est.ups.edu.ec 
💻 GitHub: [Sebastian Cabrera](https://github.com/Ccabreram1)

## Estructura
```java
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

```

## Patrones de Diseño Implementados
### Patrón Repository

```java
// Ejemplo: UserRepository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmail(String email);
    Page<UserEntity> findByNameContainingIgnoreCase(String name, Pageable pageable);
}
```

### Patrón Service
```java
// Servicio con interfaz e implementación
public interface UserService {
    Page<UserResponseDto> findAll(Pageable pageable);
    UserResponseDto findById(Long id);
    // ... otros métodos
}
@Service
public class UserServiceImpl implements UserService {
    // Implementación con transacciones
}

```
 
### Patrón DTO (Data Transfer Object)
```java
// Separación entre entidades y objetos de transferencia
public class UserResponseDto {
    private Long id;
    private String name;
    private String email;
    // ... sin información sensible como password
}
```

### Patrón Mapper
``` java
@Component
public class UserMapper {
    public UserResponseDto toDto(UserEntity user) {
        // Conversión entre entidad y DTO
    }
}
```

## Sistema de Seguridad
### Autenticación JWT
```java
// Flujo de autenticación:
// 1. Usuario envía credenciales → /api/auth/login
// 2. AuthService valida y genera JWT
// 3. Cliente incluye token en header: Authorization: Bearer <token>
// 4. JwtAuthenticationFilter valida token en cada request
```

### Roles y Permisos

* ROLE_ADMIN: Acceso completo al sistema

* ROLE_PROGRAMMER: Gestión de portafolio, proyectos y citas

* ROLE_USER: Agendar citas y ver portafolios

### Seguridad por Método
```java
@PreAuthorize("hasRole('ADMIN') or @portfolioSecurity.isOwner(#id)")
public ResponseEntity<PortfolioResponseDto> updatePortfolio(@PathVariable Long id) {
    // Solo admin o dueño puede actualizar
}
```

## Manejo de Transacciones
```java
@Service
public class AppointmentServiceImpl implements AppointmentService {
    
    @Override
    @Transactional
    public AppointmentResponseDto create(AppointmentRequestDto appointmentDto) {
        // Operaciones atómicas con rollback automático en caso de error
    }
    
    @Override
    @Transactional(readOnly = true)
    public Page<AppointmentResponseDto> findAll(Pageable pageable) {
        // Consultas de solo lectura optimizadas
    }
}
```

## Sistema de Notificaciones
### Arquitectura
``` java
@Service
public class EmailService {
    
    @Async  // Ejecución asíncrona
    public void sendAppointmentNotification(AppointmentEntity appointment) {
        // Envío de email sin bloquear hilo principal
    }
}
``` 

### Programación de Tareas
```java
@Service
public class NotificationScheduler {
    
    @Scheduled(cron = "0 0 * * * *")  // Cada hora
    public void sendAppointmentReminders() {
        // Envía recordatorios automáticos
    }
}
```

## Validación y Manejo de Errores
### Validación de Datos
``` java
public class AppointmentRequestDto {
    @NotNull(message = "El ID del programador es obligatorio")
    private Long programmerId;
    
    @Future(message = "La fecha debe ser en el futuro")
    private LocalDateTime dateTime;
}
```

### Excepciones Personalizadas
```java
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(NotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse(ex.getMessage()));
    }
}
```
## Integración entre Módulos
### Relaciones de Base de Datos
```java
sql
-- Relaciones principales:
-- User (1) ── (1) Portfolio
-- Portfolio (1) ── (N) Project
-- User (1) ── (N) Appointment (como programador o cliente)
-- User (1) ── (N) Availability
-- User (1) ── (N) Notification
``` 

## Comunicación entre Servicios
```java
@Service
public class AppointmentServiceImpl {
    
    // Inyección de dependencias
    private final EmailService emailService;
    private final NotificationService notificationService;
    
    public AppointmentResponseDto approve(Long id, String responseMessage) {
        // 1. Actualiza estado de cita
        // 2. Envía notificación por email
        emailService.sendAppointmentApproval(appointment);
        // 3. Crea notificación en sistema
        notificationService.sendAppointmentStatusChange(appointmentId, "APPROVED", responseMessage);
    }
}
```

## Configuración y Despliegue
### Configuración Externa
```java
yaml
# application.yaml
spring:
    datasource:
        url: jdbc:postgresql://localhost:5432/devdb
        username: ups
        password: ups123
        
jwt:
    secret: "portfolioDevSecretKey2024ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    expiration: 86400000  # 24 horas

```

### Inicialización de Datos
```java
@Configuration
public class DataInitializer {
    
    @Bean
    @Order(1)
    public CommandLineRunner initRoles(RoleRepository roleRepository) {
        // Crea roles por defecto (ADMIN, PROGRAMMER, USER)
    }
    
    @Bean
    @Order(2)
    public CommandLineRunner initAdminUser() {
        // Crea usuario administrador por defecto
    }
}
```

# Endpoints REST
## Autenticación (`/api/auth`)

### Público

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **POST** | `/api/auth/login` | Iniciar sesión | Público |
| **POST** | `/api/auth/register` | Registrar nuevo usuario | Público |

---

## Usuarios (`/api/users`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/users` | Listar todos los usuarios | ADMIN |
| **GET** | `/api/users/{id}` | Obtener usuario por ID | ADMIN o propio usuario |
| **POST** | `/api/users` | Crear nuevo usuario | ADMIN |
| **PUT** | `/api/users/{id}` | Actualizar usuario | ADMIN o propio usuario |
| **DELETE** | `/api/users/{id}` | Eliminar usuario | ADMIN |
| **GET** | `/api/users/programmers` | Listar programadores | Público |
| **GET** | `/api/users/search` | Buscar usuarios | ADMIN |

---

## Portafolios (`/api/portfolios`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/portfolios` | Listar portafolios | Público |
| **GET** | `/api/portfolios/{id}` | Obtener portafolio por ID | Público |
| **GET** | `/api/portfolios/user/{userId}` | Obtener portafolio de usuario | Público |
| **POST** | `/api/portfolios` | Crear portafolio | ADMIN o PROGRAMMER |
| **PUT** | `/api/portfolios/{id}` | Actualizar portafolio | ADMIN o dueño |
| **DELETE** | `/api/portfolios/{id}` | Eliminar portafolio | ADMIN o dueño |
| **GET** | `/api/portfolios/speciality/{speciality}` | Filtrar por especialidad | Público |
| **GET** | `/api/portfolios/available` | Portafolios disponibles | Público |
| **GET** | `/api/portfolios/search` | Búsqueda avanzada | Público |

---

## Proyectos (`/api/projects`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/projects` | Listar proyectos | Público |
| **GET** | `/api/projects/{id}` | Obtener proyecto por ID | Público |
| **GET** | `/api/projects/portfolio/{portfolioId}` | Proyectos de portafolio | Público |
| **GET** | `/api/projects/type/{projectType}` | Filtrar por tipo | Público |
| **POST** | `/api/projects` | Crear proyecto | ADMIN o PROGRAMMER |
| **PUT** | `/api/projects/{id}` | Actualizar proyecto | ADMIN o dueño del portafolio |
| **DELETE** | `/api/projects/{id}` | Eliminar proyecto | ADMIN o dueño del portafolio |
| **GET** | `/api/projects/search` | Búsqueda avanzada | Público |
| **GET** | `/api/projects/portfolio/{portfolioId}/count` | Contar proyectos | Público |

---

## Citas (`/api/appointments`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/appointments` | Listar todas las citas | ADMIN |
| **GET** | `/api/appointments/{id}` | Obtener cita por ID | ADMIN o involucrado |
| **GET** | `/api/appointments/programmer/{programmerId}` | Citas de programador | ADMIN o propio programador |
| **GET** | `/api/appointments/client/{clientId}` | Citas de cliente | ADMIN o propio cliente |
| **POST** | `/api/appointments` | Crear cita | USER, PROGRAMMER o ADMIN |
| **PUT** | `/api/appointments/{id}/approve` | Aprobar cita | ADMIN o programador de la cita |
| **PUT** | `/api/appointments/{id}/reject` | Rechazar cita | ADMIN o programador de la cita |
| **PUT** | `/api/appointments/{id}/complete` | Completar cita | ADMIN o programador de la cita |
| **PUT** | `/api/appointments/{id}/cancel` | Cancelar cita | ADMIN, cliente o programador |
| **DELETE** | `/api/appointments/{id}` | Eliminar cita | ADMIN |
| **GET** | `/api/appointments/upcoming` | Citas próximas | Autenticado |
| **GET** | `/api/appointments/status/{status}` | Filtrar por estado | Autenticado |
| **GET** | `/api/appointments/search` | Búsqueda avanzada | Autenticado |

---

## Disponibilidad (`/api/availabilities`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/availabilities/programmer/{programmerId}` | Disponibilidad de programador | Público |
| **POST** | `/api/availabilities` | Crear disponibilidad | ADMIN o PROGRAMMER |
| **PUT** | `/api/availabilities/{id}` | Actualizar disponibilidad | ADMIN o dueño |
| **DELETE** | `/api/availabilities/{id}` | Eliminar disponibilidad | ADMIN o dueño |
| **GET** | `/api/availabilities/programmer/{programmerId}/available` | Horarios disponibles | Público |
| **PATCH** | `/api/availabilities/{id}/toggle` | Activar/desactivar | ADMIN o dueño |

---

## Notificaciones (`/api/notifications`)

| Método | Endpoint | Descripción | Roles Permitidos |
|---|---|---|---|
| **GET** | `/api/notifications` | Listar todas | ADMIN |
| **GET** | `/api/notifications/{id}` | Obtener notificación | ADMIN o dueño |
| **GET** | `/api/notifications/user/{userId}` | Notificaciones de usuario | ADMIN o propio usuario |
| **GET** | `/api/notifications/user/{userId}/unread` | Notificaciones no leídas | ADMIN o propio usuario |
| **GET** | `/api/notifications/user/{userId}/count-unread` | Contar no leídas | ADMIN o propio usuario |
| **POST** | `/api/notifications` | Crear notificación | ADMIN |
| **POST** | `/api/notifications/send-appointment-notification` | Notificación de cita | ADMIN |
| **POST** | `/api/notifications/send-reminder` | Recordatorio | ADMIN |
| **PUT** | `/api/notifications/{id}/mark-as-read` | Marcar como leída | ADMIN o dueño |
| **PUT** | `/api/notifications/user/{userId}/mark-all-as-read` | Marcar todas como leídas | ADMIN o propio usuario |
| **DELETE** | `/api/notifications/{id}` | Eliminar notificación | ADMIN |
| **DELETE** | `/api/notifications/user/{userId}` | Eliminar todas de usuario | ADMIN o propio usuario |
| **GET** | `/api/notifications/types` | Tipos de notificación | Público |

## Link Render Backend
[D&S | DevStudio](https://davilam3.github.io/icc-ppw-proyecto-portafolio/inicio)
## Link Github Pages
[D&S | Plataform](https://dc-plataform.onrender.com)