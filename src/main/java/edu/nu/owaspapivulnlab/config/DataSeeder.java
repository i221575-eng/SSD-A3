/**
 * -----------------------------------------------------------------------------
 * File: DataSeeder.java
 * Project: OWASP API Vulnerable Lab - Secure Version
 * -----------------------------------------------------------------------------
 * Description:
 * This configuration class seeds initial test users and accounts into the database
 * when the application starts. It now uses BCrypt hashing for password storage,
 * replacing the previous insecure plaintext approach.
 *
 * Key Security Fixes Implemented:
 * 1. Injected PasswordEncoder bean to hash passwords using BCrypt.
 * 2. Ensured all seeded users have securely stored hashed passwords.
 * 3. Prevented any sensitive data (plaintext passwords) from being stored or logged.
 *
 * This fix mitigates:
 * → OWASP A3:2017 - Sensitive Data Exposure (A2:2021 - Cryptographic Failures)
 * by ensuring that no plaintext credentials are stored in the database.
 *
 * -----------------------------------------------------------------------------
 * Author: Abubakkar (Student - Secure Coding Assignment)
 * Date: October 2025
 * -----------------------------------------------------------------------------
 */

package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

/**
 * TASK 1:
 * Seed demo users but store passwords hashed using PasswordEncoder (BCrypt).
 */
@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder encoder) {
        return args -> {
            if (users.count() == 0) {
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(encoder.encode("alice123"))  // hashed with BCrypt
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build());

                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(encoder.encode("bob123"))    // hashed with BCrypt
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build());

                accounts.save(Account.builder()
                        .ownerUserId(u1.getId())
                        .iban("PK00-ALICE")
                        .balance(1000.0)
                        .build());

                accounts.save(Account.builder()
                        .ownerUserId(u2.getId())
                        .iban("PK00-BOB")
                        .balance(5000.0)
                        .build());
            }
        };
    }
}
