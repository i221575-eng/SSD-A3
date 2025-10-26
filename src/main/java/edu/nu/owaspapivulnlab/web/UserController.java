package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.util.LoggingUtils;
import java.util.Optional;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * TASK 3:
 * - Protect user resources: only owner or admin can view
 * - Prevent mass-assignment: create accepts DTO and server assigns role/isAdmin
 * - Stop returning full AppUser entity (avoid password exposure)
 *
 * TASK 4 (Data Exposure Control) applied:
 * - UserRes is a DTO mapping only id, username and email; controllers never return AppUser directly.
 * - All create/list/get responses use UserRes to avoid exposing password, role or isAdmin.
 *
 * TASK 6 (Secure Logging): log user create/delete/search actions with limited info.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    public static class UserRes {
        public Long id;
        public String username;
        public String email;
        public UserRes(AppUser u) { this.id = u.getId(); this.username = u.getUsername(); this.email = u.getEmail(); }
    }

    public static class CreateUserReq {
        @NotBlank public String username;
        @NotBlank public String password;
        @Email public String email;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        AppUser user = users.findById(id).orElse(null);
        if (user == null) {
            log.warn("User lookup not found id={}", id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(java.util.Collections.singletonMap("error","not_found"));
        }

        if (auth == null) {
            log.warn("Unauthorized user GET attempt id={} by anonymous", id);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error","forbidden"));
        }

        String authUsername = auth.getName();
        Optional<AppUser> optPrincipalUser = users.findByUsername(authUsername);
        if (!optPrincipalUser.isPresent()) {
            log.warn("Authenticated principal not found in DB: principal={}", authUsername);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(java.util.Collections.singletonMap("error","forbidden"));
        }
        AppUser principalUser = optPrincipalUser.get();

        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        if (!isAdmin && !principalUser.getId().equals(user.getId())) {
            log.warn("Forbidden user GET id={} attempted by principal={}", id, authUsername);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(java.util.Collections.singletonMap("error","forbidden"));
        }

        log.info("User profile accessed id={} by principal={}", id, LoggingUtils.maskUsername(authUsername));
        return ResponseEntity.ok(new UserRes(user));
    }

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserReq req, Authentication auth) {
        log.info("User create requested for username='{}' by principal={}", LoggingUtils.maskUsername(req.username), auth == null ? "<anonymous>" : auth.getName());
        if (users.findByUsername(req.username).isPresent()) {
            log.warn("User create failed - username taken='{}'", LoggingUtils.maskUsername(req.username));
            return ResponseEntity.status(HttpStatus.CONFLICT).body(java.util.Collections.singletonMap("error","username_taken"));
        }
        AppUser u = AppUser.builder()
                .username(req.username)
                .password(passwordEncoder.encode(req.password)) // hashed
                .email(req.email)
                .role("USER")    // server-assigned
                .isAdmin(false)
                .build();
        AppUser saved = users.save(u);

        log.info("User created id={} username='{}' by principal={}", saved.getId(), LoggingUtils.maskUsername(saved.getUsername()), auth == null ? "<anonymous>" : auth.getName());
        // Fix (Task 4): return only safe fields via UserRes DTO
        return ResponseEntity.status(HttpStatus.CREATED).body(new UserRes(saved));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        boolean isAdmin = auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            log.warn("Unauthorized delete attempt id={} by principal={}", id, auth == null ? "<anonymous>" : auth.getName());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(java.util.Collections.singletonMap("error","forbidden"));
        }
        users.deleteById(id);
        log.info("User deleted id={} by admin={}", id, auth.getName());
        return ResponseEntity.ok(java.util.Collections.singletonMap("status","deleted"));
    }

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        // restrict search to admins to avoid enumeration
        boolean isAdmin = auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            log.warn("Unauthorized user search attempted by principal={}", auth == null ? "<anonymous>" : auth.getName());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(java.util.Collections.singletonMap("error","forbidden"));
        }
        log.info("User search executed by admin={} query='{}'", auth.getName(), q);
        List<UserRes> results = users.search(q).stream().map(UserRes::new).collect(Collectors.toList());
        return ResponseEntity.ok(results);
    }
}
