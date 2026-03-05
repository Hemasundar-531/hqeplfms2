package com.company.flowmanagement.controller;

import com.company.flowmanagement.model.Employee;
import com.company.flowmanagement.repository.EmployeeRepository;
import com.company.flowmanagement.repository.O2DConfigRepository;
import com.company.flowmanagement.service.EmployeeService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/api/employees")
public class EmployeeApiController {

    private final EmployeeRepository employeeRepository;
    private final EmployeeService employeeService;
    private final com.company.flowmanagement.repository.UserRepository userRepository;
    private final O2DConfigRepository o2dConfigRepository;
    private final PasswordEncoder passwordEncoder;

    public EmployeeApiController(EmployeeRepository employeeRepository,
            EmployeeService employeeService,
            com.company.flowmanagement.repository.UserRepository userRepository,
            O2DConfigRepository o2dConfigRepository,
            PasswordEncoder passwordEncoder) {
        this.employeeRepository = employeeRepository;
        this.employeeService = employeeService;
        this.userRepository = userRepository;
        this.o2dConfigRepository = o2dConfigRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public ResponseEntity<?> list(java.security.Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        com.company.flowmanagement.model.User admin = userRepository.findByUsername(principal.getName());
        if (admin == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("User not found");
        }

        // Admin sees ALL employees (Active, Hold, Deleted) to allow management/restore
        List<Employee> employees = employeeRepository.findByAdminId(admin.getId());

        // Attach display password for UI toggle
        for (Employee emp : employees) {
            String displayPwd = EmployeeService.DEFAULT_EMPLOYEE_PASSWORD;
            if (emp.getName() != null) {
                com.company.flowmanagement.model.User user = userRepository.findByUsername(emp.getName());
                if (user != null && user.getRawPassword() != null && !user.getRawPassword().isBlank()) {
                    displayPwd = user.getRawPassword();
                }
            }
            emp.setPassword(displayPwd);
        }

        // Filter FMS folders by permissions (ADMIN_FMS:{id})
        List<com.company.flowmanagement.model.O2DConfig> folders = new ArrayList<>();
        List<String> perms = admin.getPermissions();
        if (perms != null) {
            List<String> folderIds = new ArrayList<>();
            for (String perm : perms) {
                if (perm.startsWith("ADMIN_FMS:")) {
                    folderIds.add(perm.substring("ADMIN_FMS:".length()));
                }
            }
            if (!folderIds.isEmpty()) {
                folders = (List<com.company.flowmanagement.model.O2DConfig>) o2dConfigRepository.findAllById(folderIds);
            }
        }

        return ResponseEntity.ok(Map.of(
                "employees", employees,
                "fmsFolders", folders));
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody Employee employee, java.security.Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        com.company.flowmanagement.model.User admin = userRepository.findByUsername(principal.getName());
        if (admin != null) {
            employee.setAdminId(admin.getId());
        }
        try {
            Employee saved = employeeService.createEmployee(employee);
            return ResponseEntity.status(HttpStatus.CREATED).body(saved);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to add employee. Please try again."));
        }
    }

    /**
     * Full employee update: name, email, department, status, password.
     * If name changes the linked User's username is updated too.
     * If password is provided it is re-hashed.
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable("id") String id, @RequestBody Map<String, Object> body) {
        return employeeRepository.findById(id)
                .<ResponseEntity<?>>map(existing -> {
                    String oldName = existing.getName();

                    String newName = body.get("name") != null ? body.get("name").toString().trim() : null;
                    String newEmail = body.get("email") != null ? body.get("email").toString().trim() : null;
                    String newDept = body.get("department") != null ? body.get("department").toString().trim() : null;
                    String newStatus = body.get("status") != null ? body.get("status").toString().trim() : null;
                    String newPassword = body.get("password") != null ? body.get("password").toString().trim() : null;

                    // Validate name uniqueness if name changed
                    if (newName != null && !newName.isEmpty() && !newName.equals(oldName)) {
                        com.company.flowmanagement.model.User conflict = userRepository.findByUsername(newName);
                        if (conflict != null) {
                            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                    .body(Map.of("error",
                                            "An employee with the name \"" + newName + "\" already exists."));
                        }
                    }

                    if (newName != null && !newName.isEmpty())
                        existing.setName(newName);
                    if (newEmail != null && !newEmail.isEmpty())
                        existing.setEmail(newEmail);
                    if (newDept != null && !newDept.isEmpty())
                        existing.setDepartment(newDept);
                    if (newStatus != null && !newStatus.isEmpty())
                        existing.setStatus(newStatus);

                    employeeRepository.save(existing);

                    // Update the linked User account
                    com.company.flowmanagement.model.User user = userRepository.findByUsername(oldName);
                    if (user != null) {
                        // Rename username if name changed
                        if (newName != null && !newName.isEmpty() && !newName.equals(oldName)) {
                            user.setUsername(newName);
                        }
                        if (newEmail != null && !newEmail.isEmpty()) {
                            user.setEmail(newEmail);
                        }
                        if (newPassword != null && !newPassword.isEmpty()) {
                            user.setPassword(passwordEncoder.encode(newPassword));
                            user.setRawPassword(newPassword);
                        }
                        if (newStatus != null && !newStatus.isEmpty()) {
                            user.setEnabled("Active".equalsIgnoreCase(newStatus));
                        }
                        userRepository.save(user);
                    }

                    return ResponseEntity.ok(Map.of("success", true));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * PATCH /{id}/status — Update only the status field and sync User.enabled.
     * Active = enabled=true; Hold or Deleted = enabled=false.
     */
    @PatchMapping("/{id}/status")
    public ResponseEntity<?> updateStatus(@PathVariable("id") String id,
            @RequestBody Map<String, String> body) {
        String newStatus = body.get("status");
        if (newStatus == null || newStatus.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "status is required"));
        }
        if (!newStatus.equals("Active") && !newStatus.equals("Hold") && !newStatus.equals("Deleted")) {
            return ResponseEntity.badRequest().body(Map.of("error", "status must be Active, Hold, or Deleted"));
        }
        return employeeRepository.findById(id)
                .map(existing -> {
                    existing.setStatus(newStatus);
                    employeeRepository.save(existing);

                    if (existing.getName() != null) {
                        com.company.flowmanagement.model.User user = userRepository.findByUsername(existing.getName());
                        if (user != null) {
                            user.setEnabled("Active".equalsIgnoreCase(newStatus));
                            userRepository.save(user);
                        }
                    }
                    return ResponseEntity.ok(Map.of("success", true, "status", newStatus));
                })
                .map(r -> (ResponseEntity<?>) r)
                .orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/permissions")
    public ResponseEntity<?> updatePermissions(@PathVariable("id") String id,
            @RequestBody List<String> permissions) {
        try {
            java.util.Optional<Employee> employeeOpt = employeeRepository.findById(id);
            if (employeeOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            Employee existing = employeeOpt.get();

            existing.setPermissions(permissions != null ? permissions : new ArrayList<>());
            Employee saved = employeeRepository.save(existing);

            com.company.flowmanagement.model.User user = userRepository.findByUsername(existing.getName());
            if (user != null) {
                user.setPermissions(new ArrayList<>(permissions));
                userRepository.save(user);
            }

            return ResponseEntity.ok(saved);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error updating permissions: " + e.getMessage()));
        }
    }

    /**
     * Hard delete: removes both the Employee record and the linked User login
     * account.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") String id) {
        return employeeRepository.findById(id)
                .map(emp -> {
                    // Delete linked User login account
                    if (emp.getName() != null) {
                        com.company.flowmanagement.model.User user = userRepository.findByUsername(emp.getName());
                        if (user != null) {
                            userRepository.delete(user);
                        }
                    }
                    employeeRepository.delete(emp);
                    return ResponseEntity.<Void>noContent().build();
                })
                .orElse(ResponseEntity.<Void>notFound().build());
    }

    @GetMapping("/me")
    public ResponseEntity<Employee> getCurrentUser(org.springframework.security.core.Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String username = authentication.getName();
        return employeeRepository.findByName(username)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
