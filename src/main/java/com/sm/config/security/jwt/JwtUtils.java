package com.sm.config.security.jwt;

import com.sm.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expirationMs}")
    private int expirationMs;


    private final UserService userService;

    public String generateJwtToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);
        claims.put("roles", List.of(userService.getRoles(username)));
        return Jwts.builder().setClaims(claims).setIssuedAt(now).setExpiration(expiration).signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public String getUsernameFromJwtToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        return claims.get("username", String.class);
    }

    public Claims getClaimFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

    }

    public boolean validate(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

            if (claims.getExpiration().before(Date.from(Instant.now()))) {
                return false; // token has expired
            }

            return true; // token is valid
        } catch (Exception e) {
            return false; // token is invalid
        }
    }
}

