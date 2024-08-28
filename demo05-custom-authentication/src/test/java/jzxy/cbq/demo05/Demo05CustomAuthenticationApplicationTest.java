package jzxy.cbq.demo05;

import jakarta.annotation.Resource;
import jzxy.cbq.demo05.service.AccountService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class Demo05CustomAuthenticationApplicationTest {

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
        assertEquals(0, service.list().size(), "account list size != 0");
    }

    @Test
    void testPasswordEncoder() {
        System.out.println(encoder.encode("123456"));
    }
}