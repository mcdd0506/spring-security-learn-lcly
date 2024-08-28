package jzxy.cbq.demo06;

import jakarta.annotation.Resource;
import jzxy.cbq.demo06.service.AccountService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class Demo06JWTApplicationTest {

    @Resource
    AccountService service;
    @Resource
    ApplicationContext context;
    @Resource
    BCryptPasswordEncoder encoder;

    @Test
    void contextLoads() {
        for (String bean : context.getBeanDefinitionNames()) {
            System.out.println("bean = " + bean);
        }
    }

    @Test
    void testDB() {
        assertEquals(1, service.list().size(), "account list size != 1");
    }

    @Test
    void testPasswordEncoder() {
        System.out.println(encoder.encode("123456"));
    }
}