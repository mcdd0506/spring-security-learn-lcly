package jzxy.cbq.common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.UUID;

/**
 * JWTUtils
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/29 12:25
 */
public class JWTUtils {
    private static final String SECRET = "123456";
    private static final Long EXPIRE = 1000 * 60 * 60 * 24 * 7L;

    /**
     * 生成 token
     *
     * @param subject subject
     * @return token
     */
    public static String generateToken(String subject) {
        return Jwts.builder()
                // 头部
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                // 载荷
                .setId(UUID.randomUUID().toString())
                .setIssuer("demo06@issuer")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))
                .setSubject(subject)
                // 签名
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    /**
     * 解析 token
     *
     * @param token token
     * @return Claims
     */
    public static Claims verifyToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
