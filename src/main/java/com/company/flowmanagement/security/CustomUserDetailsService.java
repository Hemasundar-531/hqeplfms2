package com.company.flowmanagement.security;

import com.company.flowmanagement.model.User;
import com.company.flowmanagement.model.Employee;
import com.company.flowmanagement.repository.UserRepository;
import com.company.flowmanagement.repository.EmployeeRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final EmployeeRepository employeeRepository;

    public CustomUserDetailsService(UserRepository userRepository, EmployeeRepository employeeRepository) {
        this.userRepository = userRepository;
        this.employeeRepository = employeeRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        // Respect the enabled flag for general access
        boolean enabled = user.isEnabled();
        // If it's a company (ADMIN) and on Hold, lock the account explicitly
        boolean accountNonLocked = true;
        if ("ADMIN".equals(user.getRole()) && "Hold".equals(user.getStatus())) {
            accountNonLocked = false;
        } else if ("EMPLOYEE".equals(user.getRole())) {
            // Check if their parent company is on Hold
            Employee emp = employeeRepository.findByName(username).orElse(null);
            if (emp != null && emp.getAdminId() != null) {
                User admin = userRepository.findById(emp.getAdminId()).orElse(null);
                if (admin != null && "Hold".equals(admin.getStatus())) {
                    accountNonLocked = false;
                }
            }
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                enabled, // enabled
                true, // accountNonExpired
                true, // credentialsNonExpired
                accountNonLocked, // accountNonLocked
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())));
    }
}
