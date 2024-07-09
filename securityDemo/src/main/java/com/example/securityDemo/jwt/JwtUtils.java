package com.example.securityDemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;


@Component
@Slf4j
public class JwtUtils {
    private static final Logger loggger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        log.info("bearerToken = " + bearerToken);
        loggger.debug("Authorization header :{} ", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);   // to remove Bearer with space(first 7 characters with space contained)
        }
        return null;
    }

    public String generateTokenFromUserName(UserDetails userDetails) {
        String userName = userDetails.getUsername();
        return Jwts.builder()
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()).build()
                .parseSignedClaims(token)
                .getPayload().getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    private boolean validateJwtToken(String authToken) {
        try {
            log.info("Validate ");
            Jwts.parser().verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException malformedJwtException) {
            log.info("Invalid JWT token as MalformedJwtException " + malformedJwtException.getMessage());
            loggger.error("Invalid JWT token as MalformedJwtException " + malformedJwtException.getMessage());
        } catch (ExpiredJwtException expiredJwtException) {
            log.info("JWT token is expired " + expiredJwtException.getMessage());
            loggger.error("JWT token is expired " + expiredJwtException.getMessage());
        } catch (UnsupportedJwtException unsupportedJwtException) {
            log.info("JWT token is unsupported " + unsupportedJwtException.getMessage());
            loggger.error("JWT token is unsupported " + unsupportedJwtException.getMessage());
        } catch (IllegalArgumentException illegalArgumentException) {
            log.info("JWT claims string is empty " + illegalArgumentException.getMessage());
            loggger.error("JWT claims string is empty " + illegalArgumentException.getMessage());
        }
        return false;
    }
}
