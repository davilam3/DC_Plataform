package ec.edu.ups.icc.portafolio.config.Datos;

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

    @Bean
    @Order(3)
    public CommandLineRunner initProgrammerUser(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        return args -> {

            String programmerEmail = "diana@portafolio.com";

            if (userRepository.findByEmail(programmerEmail).isEmpty()) {

                System.out.println("🧑‍💻 Creando programador por defecto...");

                RoleEntity programmerRole = roleRepository.findByName(RoleName.ROLE_PROGRAMMER)
                        .orElseThrow(() -> new RuntimeException("Rol PROGRAMMER no encontrado"));

                RoleEntity userRole = roleRepository.findByName(RoleName.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Rol USER no encontrado"));

                UserEntity programmer = new UserEntity();
                programmer.setName("Programador Demo");
                programmer.setEmail(programmerEmail);
                programmer.setPassword(passwordEncoder.encode("Diana123"));
                programmer.setBio("Programador creado desde backend");

                Set<RoleEntity> roles = new HashSet<>();
                roles.add(userRole);
                roles.add(programmerRole); // 🔑 CLAVE
                programmer.setRoles(roles);

                userRepository.save(programmer);

                System.out.println("✅ Programador creado");
                System.out.println("Email: diana@portafolio.com");
                System.out.println("Password: Diana123");
            }
        };
    }

}