package beomsic.springsecurityauth.jwt;

import beomsic.springsecurityauth.user.domain.Role;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenService {

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String ID_CLAIM = "id";
    private static final String BEARER = "Bearer ";

    private final Key key;
    private final long accessTokenExpirationInMs;
    private final long refreshTokenExpirationInMs;
    private final String accessHeader;
    private final String refreshHeader;

    public JwtTokenService(
            @Value("${jwt.secretKey}") String jwtSecret,
            @Value("${jwt.access.expiration}") String accessTokenExpirationInMs,
            @Value("${jwt.refresh.expiration}") String refreshTokenExpirationInMs,
            @Value("${jwt.access.header}") String accessHeader,
            @Value("${jwt.access.header}") String refreshHeader) {

        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpirationInMs = Long.parseLong(accessTokenExpirationInMs);
        this.refreshTokenExpirationInMs = Long.parseLong(refreshTokenExpirationInMs);
        this.accessHeader = accessHeader;
        this.refreshHeader = refreshHeader;
    }

    public String generateAccessToken(Long id) {
        Date now = new Date();
        Date expiredDate = new Date(now.getTime() + accessTokenExpirationInMs);

        Claims claims = Jwts.claims();
//        claims.put(EMAIL_CLAIM, email);
        claims.put(ID_CLAIM, id);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(ACCESS_TOKEN_SUBJECT)
                .setIssuedAt(now)
                .setExpiration(expiredDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(Long id) {
        Date now = new Date();
        Date expiredDate = new Date(now.getTime() + refreshTokenExpirationInMs);

        Claims claims = Jwts.claims();
        claims.put(ID_CLAIM, id);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(REFRESH_TOKEN_SUBJECT)
                .setIssuedAt(now)
                .setExpiration(expiredDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Long id = extractId(token);
        return new UsernamePasswordAuthenticationToken(id,
                "",
                List.of(new SimpleGrantedAuthority(Role.USER.getRole())));
    }

    public String extractEmail(String accessToken) {
        try {
            if (!isExistToken(accessToken)) {
                throw new RuntimeException();
            }
            Claims claims = getClaims(accessToken);
            return claims.get(EMAIL_CLAIM, String.class);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    public Long extractId(String token) {
        try {
            // 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
            if (!isExistToken(token)) {
                throw new RuntimeException();
            }
            Claims claims = getClaims(token);
            return claims.get(ID_CLAIM, Long.class);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }


    // todo : custom exception - jwt 관련 예외 (401)
    public void validateToken(String token) {
        if (!isExistToken(token)) {
            throw new RuntimeException();
        }
        try {
            if(isExpiredToken(token)) {
                System.out.println("만료");
                throw new RuntimeException();
            }
        } catch(SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
            throw new RuntimeException();
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            throw new RuntimeException();
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
            throw new RuntimeException();
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
            throw e;
        }
    }

    public Long getTokenExpiredIn(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration().getTime();
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isExpiredToken(String token) {
        try {
            Date expiration = getClaims(token).getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExistToken(String token) {
        return token != null && !token.isEmpty();
    }
}
