package jzxy.cbq.demo01;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

/**
 * ContextTest
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 13:24
 */
@SpringBootTest
public class Demo01ContextTest {

    private final ApplicationContext context;

    public Demo01ContextTest(ApplicationContext context) {
        this.context = context;
    }

    @Test
    void contextLoads() {
        for (String beanDefinitionName : context.getBeanDefinitionNames()) {
            System.out.println("beanDefinitionName = " + beanDefinitionName);
        }
    }
}
