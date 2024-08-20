package jzxy.cbq.demo04.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import jzxy.cbq.demo04.entity.Account;
import jzxy.cbq.demo04.mapper.AccountMapper;
import jzxy.cbq.demo04.service.AccountService;
import org.springframework.stereotype.Service;

/**
 * AccountServiceImpl
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/21 00:01
 */
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {
}
