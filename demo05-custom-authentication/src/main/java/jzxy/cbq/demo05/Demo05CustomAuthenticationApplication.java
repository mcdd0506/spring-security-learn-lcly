package jzxy.cbq.demo05;


import lombok.extern.slf4j.Slf4j;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo05CustomAuthenticationApplication
 *
 * @author: mcdd
 * @date: 2024/8/25 22:44
 * @since 1.0.0
 */
@SpringBootApplication
@MapperScan("jzxy.cbq.demo05.mapper")
@Slf4j
public class Demo05CustomAuthenticationApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo05CustomAuthenticationApplication.class, args);

        log.info("Demo05CustomAuthenticationApplication run successful ");
    }
}
