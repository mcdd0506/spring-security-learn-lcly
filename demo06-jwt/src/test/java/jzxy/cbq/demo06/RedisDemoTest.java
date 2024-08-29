package jzxy.cbq.demo06;

import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.concurrent.TimeUnit;

/**
 * RedisDemoTest
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/29 12:41
 */
@SpringBootTest
public class RedisDemoTest {

    @Resource
    private RedisTemplate<String, String> redisTemplate;

    @Test
    void testSetValue() {
        redisTemplate.opsForValue().set("key", "value", 30, TimeUnit.SECONDS);
    }

    @Test
    void testGetValue() {
        String value = redisTemplate.opsForValue().get("key");
        System.out.println("value = " + value);
    }

}
