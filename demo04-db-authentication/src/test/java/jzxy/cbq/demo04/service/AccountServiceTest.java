package jzxy.cbq.demo04.service;

import jakarta.annotation.Resource;
import jzxy.cbq.common.utils.Const;
import jzxy.cbq.demo04.entity.Account;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AccountServiceTest {

    @Resource
    AccountService service;

    @Test
    void insert() {
        boolean save = service.save(new Account("test", "123abc", "test@qq.com"));
        assertTrue(save, "保存用户失败");
    }

    @Test
    void listAccounts() {
        assertEquals(2, service.list().size(), "account list size != 2");
    }

    @Test
    void testLoadByUsername() {
        boolean exists = service.userExistsByUsername("mcdd1024");
        assertTrue(exists);
    }

    @Test
    void testLoadByEmail() {
        boolean exists = service.userExistsByEmail("mcdd1024@qq.com");
        assertTrue(exists);
    }
}