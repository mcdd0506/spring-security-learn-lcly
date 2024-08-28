package jzxy.cbq.demo05.service;


import com.baomidou.mybatisplus.extension.service.IService;
import jzxy.cbq.demo05.entity.Account;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * AccountService
 *
 * @author: mcdd
 * @date: 2024/8/25 22:47
 * @since 1.0.0
 */
public interface AccountService extends IService<Account> , UserDetailsService {
}
