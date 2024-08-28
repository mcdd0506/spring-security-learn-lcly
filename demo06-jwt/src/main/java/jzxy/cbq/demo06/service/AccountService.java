package jzxy.cbq.demo06.service;

import com.baomidou.mybatisplus.extension.service.IService;
import jzxy.cbq.demo06.auth.RegisterVo;
import jzxy.cbq.demo06.entity.Account;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * AccountService
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/21 00:01
 */
public interface AccountService extends IService<Account>, UserDetailsService, UserDetailsPasswordService {
    boolean register(RegisterVo vo);

    boolean userExistsByUsername(String username);

    boolean userExistsByEmail(String email);

    boolean updatePasswordByUsernameOrEmail(String text , String newPassword);
}
