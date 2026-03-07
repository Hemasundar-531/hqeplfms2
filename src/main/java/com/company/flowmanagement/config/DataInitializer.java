package com.company.flowmanagement.config;

import com.company.flowmanagement.model.User;
import com.company.flowmanagement.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Removed: "admin" seed user was being recreated on every startup
            // createIfMissing(userRepository, passwordEncoder, "admin", "ADMIN");
            createIfMissing(userRepository, passwordEncoder, "order", "ORDER");
            createIfMissing(userRepository, passwordEncoder, "superadmin", "SUPERADMIN");
            // Removed: default "employee" seed account — employees must be created by an
            // admin
        };
    }

    private void createIfMissing(UserRepository userRepository, PasswordEncoder encoder,
            String username, String role) {
        try {
            if (userRepository.findByUsername(username) != null) {
                return;
            }
        } catch (org.springframework.dao.IncorrectResultSizeDataAccessException e) {
            // Found duplicates, delete them and recreate
            userRepository.deleteByUsername(username);
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(encoder.encode("1234567"));
        user.setRole(role);
        userRepository.save(user);
    }
}
