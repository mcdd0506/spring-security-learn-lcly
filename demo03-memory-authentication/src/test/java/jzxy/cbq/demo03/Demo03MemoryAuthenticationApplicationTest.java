package jzxy.cbq.demo03;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
class Demo03MemoryAuthenticationApplicationTest {

    @Test
    void noOpEncoderTest(){
        String source = "123456";
        PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
        System.out.println(encoder.encode(source));
    }

    @Test
    void bCryptEncoderTest(){
        String source = "123456";
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String first = encoder.encode(source);
        System.out.println("第一次加密: " + first);
        assertTrue(encoder.matches(source, first),"第一次密码匹配错误");
        String second = encoder.encode(source);
        System.out.println("第二次加密: " + second);
        assertTrue(encoder.matches(source, first),"第二次密码匹配错误");

    }

}