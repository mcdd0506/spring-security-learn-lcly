package jzxy.cbq.demo05.service.impl;


import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import jzxy.cbq.demo05.entity.Account;
import jzxy.cbq.demo05.mapper.AccountMapper;
import jzxy.cbq.demo05.service.AccountService;
import org.springframework.stereotype.Service;

/**
 * AccountServiceImpl
 *
 * @author: mcdd
 * @date: 2024/8/25 22:47
 * @since 1.0.0
 */
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {
}
