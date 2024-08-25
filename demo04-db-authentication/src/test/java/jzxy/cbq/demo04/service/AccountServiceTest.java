package jzxy.cbq.demo04.service;

import jakarta.annotation.Resource;
import jzxy.cbq.demo04.auth.RegisterVo;
import jzxy.cbq.demo04.auth.UserNameAlreadyExistException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class AccountServiceTest {

    @Resource
    AccountService service;

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

    @Test
    void testRegisterWithAlreadyExistUsername() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("mcdd1024");
        vo.setPassword("123abc");
        vo.setEmail("not-exist@qq.com");
        assertThrows(UserNameAlreadyExistException.class, () -> service.register(vo));
    }
    @Test
    void testRegisterWithAlreadyExistEmail() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("not-exist");
        vo.setPassword("123abc");
        vo.setEmail("mcdd1024@qq.com");
        assertThrows(UserNameAlreadyExistException.class, () -> service.register(vo));
    }
    @Test
    void testRegisterWithDifferentUsername() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("mcdd01");
        vo.setPassword("123abc");
        vo.setEmail("mcdd01@qq.com");
        assertTrue(service.register(vo));
    }

    @Test
    void testUpdatePasswordByUsernameOrEmail() {
        boolean updated01 = service.updatePasswordByUsernameOrEmail("mcdd01", "updated-password");
        assertTrue(updated01);
        boolean updated02 = service.updatePasswordByUsernameOrEmail("mcdd1024@qq.com", "updated-password");
        assertTrue(updated02);
        assertThrows(UsernameNotFoundException.class, () -> service.updatePasswordByUsernameOrEmail("not-exist@qq.com", "updated-password"));
        assertThrows(UsernameNotFoundException.class, () -> service.updatePasswordByUsernameOrEmail("not-exist", "updated-password"));
    }
}