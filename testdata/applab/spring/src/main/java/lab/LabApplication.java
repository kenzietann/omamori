package lab;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// A small Spring Boot API with the default logging of Spring Boot, the Tomcat access log turned on,
// and the env endpoint of Actuator exposed by mistake.
@SpringBootApplication
@RestController
public class LabApplication {
    private static final Logger log = LoggerFactory.getLogger("AuthService");

    public static void main(String[] args) { SpringApplication.run(LabApplication.class, args); }

    @PostMapping("/auth/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if ("alice".equals(body.get("username")) && "Summer2026!".equals(body.get("password"))) {
            return ResponseEntity.ok(Map.of("token", "t"));
        }
        log.warn("Failed login for {} from {}", body.get("username"), request.getRemoteAddr());
        return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
    }

    @GetMapping("/api/items")
    public ResponseEntity<Object> items(@RequestParam(defaultValue = "") String id) {
        if (id.contains("'")) {
            log.error("org.postgresql.util.PSQLException: ERROR: syntax error at or near \"{}\"", id);
            return ResponseEntity.status(500).body(Map.of("error", "server error"));
        }
        return ResponseEntity.ok(new Object[0]);
    }
}
