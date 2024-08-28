# 进阶功能

> [!NOTE] 内容
>
> - 前后端分离下的自定义认证
> - JWT
> - 异常处理
> - 免鉴权（白名单）
> - 跨域处理
> - RememberMe
> - 会话管理

# 一、前后端分离下的自定义认证

通过前面的学习我们已经完成了 JSON 返回认证结果的功能以及 Spring Security 的认证流程我们知道 Spring Security 使用 `UsernamePasswordAuthenticationFilter` 进行认证处理，该过滤器通过获取 POST 请求中的表单数据 (username 和 password) 将其封装为 `UsernamePasswordAuthenticationToken` ,然后借助 `getAuthenticationManager` 获取  `AuthenticationManager` 调用该对象的 `authenticate` 传入上面封装好的 `UsernamePasswordAuthenticationToken` 对象完成认证

```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
        // 1. 获取 POST 请求中的表单数据 (username 和 password) 
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
        // 2. 将其封装为 `UsernamePasswordAuthenticationToken`
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        // 3. 通过 `getAuthenticationManager` 获取 AuthenticationManager 对象然后调用的 `authenticate` 传入上面封装好的 `UsernamePasswordAuthenticationToken` 对象完成认证
		return this.getAuthenticationManager().authenticate(authRequest);
	}
    
}
```

基于前后段分离开发模式的需要前段喜爱嗯亩使用 Axios 发送请求，以 JSON 格式的数据作为请求参数发送给后端，后端通过相关 Controller 获取 JSON 数据然后通过自定义认证逻辑进行认证。

## 1.1 实现

### 自定义 AuthenticationManager

认证管理器 `AuthenticationManager` 的  `authenticate` 是发起认证的起源，因此我们首先需要将其手动实现以达到自定义认证的目的

```java
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService service) {
        // 匹配合适的 AuthenticationProvider 即 DaoAuthenticationProvider
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 配置基于数据库认证的 UserDetailsService
        provider.setUserDetailsService(service);
        // 创建并返回认证管理器对象 (实现类 ProviderManager )
        return new ProviderManager(provider);
    }
```

### 创建认证 Service

```java
public interface AuthService {
    RestBean<String> login(LoginVo vo);
}
```

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;

    @Override
    public RestBean<String> login(LoginVo vo) {
        // 获取 username 和 password 并将其封装为
        String username = vo.getUsername();
        String password = vo.getPassword();
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
                password);
        // 发起认证
        try {
            Authentication authentication = authenticationManager.authenticate(authRequest);
            if (authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                return RestBean.success("认证成功");
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        return RestBean.unauthorized("认证失败");
    }
}
```

---

```java
public interface AccountMapper extends BaseMapper<Account> {
}
```

```java
public interface AccountService extends IService<Account> , UserDetailsService {
}
```

```java
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
}
```

### 创建认证 Controller

```java
@Data
public class LoginVo {
    private String username;
    private String password;
}
```

```java
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @PostMapping("/login")
    public RestBean<String> login(@RequestBody LoginVo vo){
         return service.login(vo);
    }
}

```

### 关闭默认配置

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.
                        requestMatchers("/api/auths/**").permitAll()
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable) // [!code ++]
                .formLogin(AbstractHttpConfigurer::disable); // [!code ++]
        return http.build();
    }
```

## 1.2 测试

### 通过 API 测试

```sh
curl -X "POST" "http://localhost:8084/api/auths/login" \
-H 'Content-Type: application/json' \
-d '{
  "username": "cxk",
  "password": "1234a56"
}' \

```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282253664.png)

```sh
curl -X "POST" "http://localhost:8084/api/auths/login" \
-H 'Content-Type: application/json' \
-d '{
  "username": "cxk",
  "password": "123456"
}' \

```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282253106.png)

### 通过前端页面测试

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
</head>
<body>
<div id="app">
    登陆用户: <input type="text" id="username" autocomplete="off" v-model="username">
    <br/>
    密码: <input type="password" id="password" v-model="password">
    <br/>
    <input type="button" value="登陆" @click="login">
</div>

</body>
<script>
    axios.defaults.baseURL = 'http://localhost:8084/api/auths/';
    const appConfig = {
        data() {
            return {
                username: '',
                password: '',
            };
        },
        methods: {
            login() {
                let url = "/login";
                axios.post(url, {username: this.username, password: this.password})
                    .then(res => {
                        console.log(res.data);
                    })
                    .catch(err => {
                        console.log(err.data);
                    });
            }
        },
    }
    const app = Vue.createApp(appConfig);
    app.mount('#app');
</script>
<style>
    #app #username,
    #app #password {
        width: 150px;
    }
</style>
</html>
```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282314188.png)

可以看到此处出现了 cors 跨域问题,此处我们简单处理，后续将进行单独处理

```java
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @CrossOrigin // [!code ++]
    @PostMapping("/login")
    public RestBean<String> login(@RequestBody LoginVo vo){
         return service.login(vo);
    }
}
```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282315021.png)

# 二、JWT

# 三、异常处理

# 四、免鉴权（白名单）

# 五、跨域处理

# 六、RememberMe

# 七、会话管理

