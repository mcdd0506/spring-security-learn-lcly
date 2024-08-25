package jzxy.cbq.demo05;

import jakarta.annotation.Resource;
import jzxy.cbq.demo05.service.AccountService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class Demo05CustomAuthenticationApplicationTest {

    @Resource
    AccountService service;
    @Resource
    ApplicationContext context;

    @Test
    void contextLoads() {
        for (String bean : context.getBeanDefinitionNames()) {
            System.out.println("bean = " + bean);
        }
    }

    @Test
    void testDB() {
        assertEquals(2, service.list().size(), "account list size != 2");
    }
}