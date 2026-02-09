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

    @Query("SELECT u FROM UserEntity u WHERE :role MEMBER OF u.roles")
    List<UserEntity> findByRole(RoleEntity role);

    @Query("SELECT u FROM UserEntity u WHERE :role MEMBER OF u.roles")
    Page<UserEntity> findByRole(RoleEntity role, Pageable pageable);

    @Query("SELECT u FROM UserEntity u JOIN u.roles r WHERE r.name = :roleName")
    Page<UserEntity> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    @Query("SELECT u FROM UserEntity u WHERE u.createdAt > :date")
    List<UserEntity> findByCreatedAtAfter(@Param("date") LocalDateTime date);
}
