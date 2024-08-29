package jzxy.cbq.demo06;

import cn.hutool.core.lang.UUID;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.Date;

/**
 * JWTDemoTest
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/29 12:15
 */
public class JWTDemoTest {
    private static final String SECRET = "123456";
    private static final Long EXPIRE = 1000 * 60 * 60 * 24 * 7L;

    @Test
    void testGenerateToken() {
        String username = "admin";
        String token = Jwts.builder()
                // 头部
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                // 载荷
                .setId(UUID.randomUUID().toString())
                .setIssuer("demo06@issuer")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))
                .setSubject(username)
                // 签名
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
        System.out.println("token = " + token);
    }

    @Test
    void testVerifyToken() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4MTRjZWU1Ny1iZDgwLTQ0ZGMtYWRmYS03YTM4YWY2ODRlOWYiLCJpc3MiOiJkZW1vMDZAaXNzdWVyIiwiaWF0IjoxNzI0OTA1Mzk0LCJleHAiOjE3MjU1MTAxOTQsInN1YiI6ImFkbWluIn0.TwZKaDrrT-nhK5RVVSy8pB5Dw40em0Bet3XVk-Yqduk";
        Claims body = Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
        System.out.println("body = " + body);
    }
}
