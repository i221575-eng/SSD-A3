package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.util.LoggingUtils;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Account Controller – Tasks 3, 4, 6, 9
 *
 * - Task 3: Enforce ownership (only owner or admin can access)
 * - Task 4: Use TransferRequest DTO to prevent mass assignment
 * - Task 6: Secure logging (no sensitive data in logs)
 * - Task 9: Server-side validation of amount (positive, max limit)
 */
@Validated
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private static final Logger log = LoggerFactory.getLogger(AccountController.class);
    private static final double MAX_TRANSFER = 1_000_000.0;

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // ========================================================================
    // DTO: Prevent mass assignment (Task 4)
    // ========================================================================
    public static class TransferRequest {
        @NotNull(message = "Amount is required")
        @Positive(message = "Amount must be positive")
        @Max(value = (long) MAX_TRANSFER, message = "Amount exceeds maximum allowed transfer")
        private Double amount;

        public TransferRequest() {}
        public Double getAmount() { return amount; }
        public void setAmount(Double amount) { this.amount = amount; }
    }

    // ========================================================================
    // Get balance – ownership enforced (Task 3)
    // ========================================================================
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        if (auth == null || auth.getName() == null) {
            log.warn("Unauthorized balance access attempt by anonymous for accountId={}", id);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        AppUser principal = users.findByUsername(auth.getName()).orElse(null);
        if (principal == null) {
            log.warn("Authenticated user not found: principal={}", auth.getName());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        Optional<Account> oa = accounts.findById(id);
        if (oa.isEmpty()) {
            log.warn("Balance requested for non-existing accountId={} by userId={}", id, principal.getId());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "not_found"));
        }

        Account account = oa.get();
        if (!isOwnerOrAdmin(auth, principal, account.getOwnerUserId())) {
            log.warn("Forbidden balance access: accountId={} by userId={}", id, principal.getId());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "forbidden"));
        }

        log.info("Balance viewed: accountId={} by userId={}", id, principal.getId());
        return ResponseEntity.ok(Map.of("balance", account.getBalance()));
    }

    // ========================================================================
    // Transfer money – DTO + validation + ownership + funds check (Tasks 3,4,9)
    // ========================================================================
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(
            @PathVariable Long id,
            @Valid @RequestBody TransferRequest req,
            Authentication auth) {

        double amount = req.getAmount();

        if (auth == null || auth.getName() == null) {
            log.warn("Unauthorized transfer attempt on accountId={} amount={}", id, amount);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        AppUser principal = users.findByUsername(auth.getName()).orElse(null);
        if (principal == null) {
            log.warn("Authenticated user not found during transfer: principal={}", auth.getName());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        Optional<Account> oa = accounts.findById(id);
        if (oa.isEmpty()) {
            log.warn("Transfer attempted on non-existing accountId={} amount={} by userId={}",
                    id, amount, principal.getId());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "not_found"));
        }

        Account account = oa.get();

        // Task 3: Ownership check
        if (!isOwnerOrAdmin(auth, principal, account.getOwnerUserId())) {
            log.warn("Forbidden transfer attempt: accountId={} amount={} by userId={}",
                    id, amount, principal.getId());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "forbidden"));
        }

        // Task 9: Server-side funds check
        if (account.getBalance() < amount) {
            log.warn("Insufficient funds: accountId={} requested={} balance={} by userId={}",
                    id, amount, account.getBalance(), principal.getId());
            return ResponseEntity.badRequest()
                    .body(Collections.singletonMap("error", "insufficient_funds"));
        }

        // Perform transfer
        account.setBalance(account.getBalance() - amount);
        accounts.save(account);

        log.info("Transfer successful: accountId={} amount={} by userId={} remaining={}",
                id, amount, principal.getId(), account.getBalance());

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", account.getBalance());
        return ResponseEntity.ok(response);
    }

    // ========================================================================
    // List user's own accounts (Task 3)
    // ========================================================================
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            log.warn("Unauthorized access to /mine by anonymous");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        AppUser principal = users.findByUsername(auth.getName()).orElse(null);
        if (principal == null) {
            log.warn("Authenticated user not found in DB: principal={}", auth.getName());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "unauthorized"));
        }

        log.info("Returning accounts for userId={} username={}",
                principal.getId(), LoggingUtils.maskUsername(auth.getName()));

        List<Account> myAccounts = accounts.findByOwnerUserId(principal.getId());
        return ResponseEntity.ok(myAccounts);
    }

    // ========================================================================
    // Helper: Admin or Owner?
    // ========================================================================
    private boolean isOwnerOrAdmin(Authentication auth, AppUser principal, Long ownerUserId) {
        if (principal == null || ownerUserId == null) return false;

        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));

        return isAdmin || principal.getId().equals(ownerUserId);
    }
}
