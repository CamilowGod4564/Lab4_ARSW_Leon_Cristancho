package co.edu.eci.blueprints.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
public class InMemoryUserService {
    public record AppUser(String passwordHash, String scopes) {}
    private final Map<String, AppUser> users; // username -> (hash, scopes)
    private final PasswordEncoder encoder;

    public InMemoryUserService(PasswordEncoder encoder) {
        this.encoder = encoder;
        this.users = Map.of(
                "student",   new AppUser(encoder.encode("student123"),   "blueprints.read"),
                "assistant", new AppUser(encoder.encode("assistant123"), "blueprints.read blueprints.write")
        );
    }

    public boolean isValid(String username, String rawPassword) {
        AppUser u = users.get(username);
        return u != null && encoder.matches(rawPassword, u.passwordHash());
    }

    public String scopesOf(String username) {
        AppUser u = users.get(username);
        return u == null ? "" : u.scopes();
    }
}
