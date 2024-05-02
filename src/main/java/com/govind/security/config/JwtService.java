package com.govind.security.config;

import com.govind.security.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    @Value("86400000")
    private int expiry;


    public String extractUsernameFromToken(String jwtToken) {
        return extractClaimFromToken(jwtToken, Claims::getSubject);
    }

    public Date extractExpirationDateFromToken(String jwtToken) {
        return extractClaimFromToken(jwtToken, Claims::getExpiration);
    }

    public Role extractRoleFromToken(String jwtToken) {
        return null;
    }

    public <T> T extractClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaimsFromToken(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    // Generate token without claims.
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Generate toke with claims.
    public String generateToken(Map<String, Objects> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiry))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        final String usernameFromToken = this.extractUsernameFromToken(jwtToken);
        return (usernameFromToken.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
    }

    private boolean isTokenExpired(String token) {
        final Date expiration = this.extractExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
