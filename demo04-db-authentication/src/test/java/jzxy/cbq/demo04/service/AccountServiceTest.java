package jzxy.cbq.demo04.service;

import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AccountServiceTest {

    @Resource
    AccountService service;

    @Test
    void listAccounts() {
        assertEquals(0,service.list().size(),"account list size != 0");
    }
}