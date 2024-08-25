package jzxy.cbq.demo04.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import jzxy.cbq.demo04.auth.RegisterVo;
import jzxy.cbq.demo04.entity.Account;
import jzxy.cbq.demo04.auth.UserNameAlreadyExistException;
import jzxy.cbq.demo04.mapper.AccountMapper;
import jzxy.cbq.demo04.service.AccountService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * AccountServiceImpl
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/21 00:01
 */
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    @Override
    public UserDetails loadUserByUsername(String text) throws UsernameNotFoundException {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, text).or().eq(Account::getEmail, text));
        if (Objects.isNull(account)) {
            throw new UsernameNotFoundException(text);
        }
        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Override
    public boolean register(RegisterVo vo) {
        if (this.userExistsByUsername(vo.getUsername()) || this.userExistsByEmail(vo.getEmail())) {
            throw new UserNameAlreadyExistException("用户名或邮箱已被注册");
        } else {
            Account account = new Account();
            account.setUsername(vo.getUsername());
            account.setPassword(vo.getPassword());
            account.setEmail(vo.getEmail());
            return this.save(account);
        }
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        boolean updated = this.updatePasswordByUsernameOrEmail(user.getUsername(), newPassword);
        return updated ? user : null;
    }

    @Override
    public boolean updatePasswordByUsernameOrEmail(String text, String newPassword) {
        if (!this.userExistsByUsername(text) && !this.userExistsByEmail(text)) {
            throw new UsernameNotFoundException("没有指定用户名或邮箱的用户");
        } else {
            return this.update(new LambdaUpdateWrapper<Account>()
                    .set(Account::getPassword, newPassword)
                    .in(Account::getUsername, text)
                    .or()
                    .in(Account::getEmail, text));
        }
    }



    @Override
    public boolean userExistsByUsername(String username) {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, username));
        return account != null;
    }

    @Override
    public boolean userExistsByEmail(String email) {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getEmail, email));
        return account != null;
    }
}
