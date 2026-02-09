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