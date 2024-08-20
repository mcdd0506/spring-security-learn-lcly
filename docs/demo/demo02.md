# 二、Spring Security 过滤器链

## 2.1 什么是过滤器



## 2.2 Spring Security 过滤器链

据我们前面描述的 Spring Security 主要基于过滤器链实现相关功能，而该处的过滤器链可以有以下两重含义：

1. 是一组而非一个：应用程序启动时会注册一系列的过滤器，每个过滤器都有明确的职责（实现某个方面的检查功能）
2. 有顺序而非随机：默认情况下过滤器按照顺序依次执行，每个请求都需经过完成的过滤器链的检查

通过 Spring Security 的过滤器链，我们可以轻松构建起一套完整的完全防护体系（特殊情况可配置不经过过滤器链 e.g. 登录接口、静态资源等）那么我们该如何查看当前项目中已配置的过滤器呢?

- 我们可以通过 IDEA 在启动控制台中的信息查看 Spring Security 的过滤器链 （共计 15 个过滤器）

![image-20240820195516079](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201955184.png)

```sh
2024-08-20T19:44:59.542+08:00  INFO 13148 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [
org.springframework.security.web.session.DisableEncodeUrlFilter@72906e, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@5529ff44, org.springframework.security.web.context.SecurityContextHolderFilter@f557c37, org.springframework.security.web.header.HeaderWriterFilter@6b9fdbc6, org.springframework.security.web.csrf.CsrfFilter@5d512ddb, org.springframework.security.web.authentication.logout.LogoutFilter@7af443a3, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@66c9b52f, org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@746c411c, org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter@14447be, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@574059d5, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@5856dbe4, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@20c812c8, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@5eb5da12, org.springframework.security.web.access.ExceptionTranslationFilter@32f32623, org.springframework.security.web.access.intercept.AuthorizationFilter@4b515eab
]
```

- 或者我们也可以通过 `DefaultSecurityFilterChain` 类查看

```java
public final class DefaultSecurityFilterChain implements SecurityFilterChain {

	private static final Log logger = LogFactory.getLog(DefaultSecurityFilterChain.class);

	private final RequestMatcher requestMatcher;

	private final List<Filter> filters;

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, Filter... filters) {
		this(requestMatcher, Arrays.asList(filters));
	}
    
	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		if (filters.isEmpty()) {
			logger.info(LogMessage.format("Will not secure %s", requestMatcher));
		}
		else {
			logger.info(LogMessage.format("Will secure %s with %s", requestMatcher, filters));
		}
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	}    
    
    //...
}
```

![image-20240820195652863](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201956959.png)

可以看到 `DefaultSecurityFilterChain` 实现了 `SecurityFilterChain` 接口，而后者源代码如下

```java
public interface SecurityFilterChain {

	boolean matches(HttpServletRequest request);

	List<Filter> getFilters();

}
```

其中有 `List<Filter> getFilters();` 方法其在 `DefaultSecurityFilterChain` 中相关代码如下

```java
	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		if (filters.isEmpty()) {
			logger.info(LogMessage.format("Will not secure %s", requestMatcher));
		}
		else {
			logger.info(LogMessage.format("Will secure %s with %s", requestMatcher, filters));
		}
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	} 
```

注意到 `this.filters = new ArrayList<>(filters);` 对 filters 完成了赋值操作，因此我们在此处设立一个断点然后 DEBUG 进行查看

![image-20240820200126907](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202001015.png)

可以看到 filters 数组中的内容和第一种方式中控制台输出的内容一致，下面让我们认识其中几个过滤器

> [!NOTE]
>
> 因为都是过滤器所以我们主要关注其 doFilter 方法

- SecurityContextHolderFilter

该过滤器负责维护 SecurityContext（安全上下文）即一个存储了当前用户的认证信息如身份、权限等的对象，其内部包含两个重要的属性：

- securityContextRepository ：定义了获取 SecurityContext 对象的方式，默认通过 session 对象中获取 SecurityContext 对象
- securityContextHolderStrategy：定义了获取 SecurityContext 对象的存储策略，默认使用 ThreadLocal 策略，其负责将安全上下文绑定到当前线程中，一旦绑定成功后面的过滤器可以直接通过 SecurityContextHolder 来获取当前用户的安全信息，而无需显示地传递安全上下文

我们可以通过其源代码进行了解：

![image-20240820201413642](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202014761.png)

其 doFilter 方法如下

```java
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
        // 1. 针对当前请求通过 FILTER_APPLIED 字段判断当前请求是否已经被过滤过 如果是则直接 return 反之继续执行
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
        // 2. 针对当前请求 FILTER_APPLIED 字段设置为 true （将当前过滤器标记为已执行）
        // 然后通过 securityContextRepository.loadDeferredContext(request) 获取 SecurityContext 对象并
        // 赋值给 deferredContext
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		Supplier<SecurityContext> deferredContext = this.securityContextRepository.loadDeferredContext(request);
		try {
            // 3. 将 deferredContext 即 SecurityContext 对象通过
            // securityContextHolderStrategy.setDeferredContext(deferredContext) 
            // 的方式 （默认存储策略为 ThreadLocal ）将当前 SecurityContext 对象绑定到当前线程便于后续传递（一旦绑定成功
            // 后面的过滤器可以直接通过 SecurityContextHolder 来获取当前用户的安全信息，而无需显示地传递安全上下文）
			this.securityContextHolderStrategy.setDeferredContext(deferredContext);
			chain.doFilter(request, response);
		}
		finally {
			this.securityContextHolderStrategy.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
	}
```

securityContextHolderStrategy 默认使用 ThreadLocal 策略

![image-20240820203257097](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202032213.png)

> [!CAUTION] 注意
>
> SpringSecurity 5.4 之后，SecurityContextHolder 继任 SecurityContextPersistenceFilter 的工作

- UsernamePasswordAuthenticationFilter

该过滤器负责处理基于表单的登录认证请求，默认匹配 URL 为 /login 且必须为 POST 请求主要用于解析用户名和密码，并将两者封装到一个 Authentication 对象，然后发起真正的认证请求

```java
	@Override
	// 准备认证方法
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
        // 仅支持 POST 请求
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
        // 解析用户名和密码并将其封装为 UsernamePasswordAuthenticationToken 对象
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        // 发起真正的请求
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```

默认匹配 URL 为 /login

![image-20240820203709400](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202037522.png)

- ExceptionTranslationFilter

该过滤器负责处理 Spring Security 中的异常其只处理两大类异常：AccessDeniedException 访问异常 和 AuthenticationException 认证异常

```java
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			chain.doFilter(request, response);
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
            // AuthenticationException 认证异常
			RuntimeException securityException = (AuthenticationException) this.throwableAnalyzer
				.getFirstThrowableOfType(AuthenticationException.class, causeChain);
			if (securityException == null) {
                // AccessDeniedException 访问异常
				securityException = (AccessDeniedException) this.throwableAnalyzer
					.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
			}
			if (securityException == null) {
				rethrow(ex);
			}
			if (response.isCommitted()) {
				throw new ServletException("Unable to handle the Spring Security Exception "
						+ "because the response is already committed.", ex);
			}
			handleSpringSecurityException(request, response, chain, securityException);
		}
	}
```

- AuthorizationFilter

该过滤器负责在识别用户身份后（验证操作完成）甄别用户是否具备访问特定资源的权限（授权过程）也成为 鉴权过滤器，是 Spring Security 过滤器链的最后一关其后面就是请求想要访问的真是资源

> [!CAUTION] 注意
>
> SpringSecurity 5.4 之后，AuthorizationFilter 继任 FilterSecurityInterceptor 的工作

- DefaultLoginPageGeneratingFilter

该过滤器负责生成默认的登录页面

![image-20240820204915704](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202049826.png)

通过下面代码生成页面

```java
private String generateLoginPageHtml(HttpServletRequest request, boolean loginError, boolean logoutSuccess) {
		String errorMsg = loginError ? getLoginErrorMessage(request) : "Invalid credentials";
		String contextPath = request.getContextPath();
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Please sign in</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath
					+ this.authenticationUrl + "\">\n");
			sb.append("        <h2 class=\"form-signin-heading\">Please sign in</h2>\n");
			sb.append(createError(loginError, errorMsg) + createLogoutSuccess(logoutSuccess) + "        <p>\n");
			sb.append("          <label for=\"username\" class=\"sr-only\">Username</label>\n");
			sb.append("          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter
					+ "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n");
			sb.append("        </p>\n");
			sb.append("        <p>\n");
			sb.append("          <label for=\"password\" class=\"sr-only\">Password</label>\n");
			sb.append("          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter
					+ "\" class=\"form-control\" placeholder=\"Password\" required>\n");
			sb.append("        </p>\n");
			sb.append(createRememberMe(this.rememberMeParameter) + renderHiddenInputs(request));
			sb.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n");
			sb.append("      </form>\n");
		}
		if (this.oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : this.oauth2AuthenticationUrlToClientName
				.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		if (this.saml2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with SAML 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> relyingPartyUrlToName : this.saml2AuthenticationUrlToProviderName
				.entrySet()) {
				sb.append(" <tr><td>");
				String url = relyingPartyUrlToName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String partyName = HtmlUtils.htmlEscape(relyingPartyUrlToName.getValue());
				sb.append(partyName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		sb.append("</div>\n");
		sb.append("</body></html>");
		return sb.toString();
	}
```

也就是我们看到的 `http://localhost:8080/login` 页面

![image-20240820205015316](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202050436.png)

- LogoutFilter

该过滤器负责处理用户注销登录请求，默认匹配 URL 为 /logout 它会清除本次认证相关信息包括用户的会话信息、安全上下文信息和 Remember-Me 、Cookie 等以确保用户完全退出系统

```java
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (requiresLogout(request, response)) {
			Authentication auth = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Logging out [%s]", auth));
			}
			this.handler.logout(request, response, auth);
			this.logoutSuccessHandler.onLogoutSuccess(request, response, auth);
			return;
		}
		chain.doFilter(request, response);
	}
```

![image-20240820205631814](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202056958.png)

- DefaultLogoutPageGeneratingFilter

该过滤器负责生成默认的注销页面

![image-20240820205111442](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202051602.png)

通过下面代码生成页面

```java
private void renderLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Confirm Log Out?</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" "
				+ "crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");
		sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + request.getContextPath()
				+ "/logout\">\n");
		sb.append("        <h2 class=\"form-signin-heading\">Are you sure you want to log out?</h2>\n");
		sb.append(renderHiddenInputs(request)
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Log Out</button>\n");
		sb.append("      </form>\n");
		sb.append("    </div>\n");
		sb.append("  </body>\n");
		sb.append("</html>");
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().write(sb.toString());
	}
```

也就是我们看到的 `http://localhost:8080/logout` 页面

![image-20240820205152264](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202051393.png)

## 2.3 SecurityProperties

存储 Spring Security 需要的一些参数

![image-20240820205817835](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202058985.png)

```java
public static class User {
		/**
		 * Default user name.
		 */
		private String name = "user";

		/**
		 * Password for the default user name.
		 */
		private String password = UUID.randomUUID().toString();

		/**
		 * Granted roles for the default user name.
		 */
		private List<String> roles = new ArrayList<>();

		private boolean passwordGenerated = true;
}
```

从上面代码不难看出为什么默认情况下登录的用户名为 user 以及在控制台输出的密码为什么是一串 （UUID）

![image-20240820163314501](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201633613.png)

## 2.4 如何定制过滤器链

Spring Security 的默认过滤器链允许根据需求进行定制，一般步骤如下：

1. 创建 SecurityConfiguration 配置类
   - 如果是 Spring Boot 项目则无需添加 @EnableWebSecurity 注解
2. 创建 SecurityFilterChain 对象并将其添加为 Bean （参数为： HttpSecurity http）
3. 按需定制过滤器

> [!CAUTION] 注意
>
> Spring Security 6.1 开始，配置类不再基于 WebSecurityConfigurerAdapter 创建而是通过 创建 SecurityFilterChain 对象 （参数为： HttpSecurity http）

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.build();
    }
}
```

自定义拦截范围

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->  // [!code focus:4]
                requests.anyRequest().authenticated());
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }
```

![image-20240820212504327](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202125511.png)

其中 `http.formLogin(Customizer.withDefaults());` 与 ` http.httpBasic(Customizer.withDefaults());` 的区别主要在于

- `http.formLogin(Customizer.withDefaults());` 基于表单封装参数

![image-20240820212759916](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202128082.png)

- ` http.httpBasic(Customizer.withDefaults());` 通过请求头封装参数

![image-20240820212848226](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202128376.png)

一般情况下我们只需保留一种即可（此处保留 http.formLogin(Customizer.withDefaults()); 方式）

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
                requests.anyRequest().authenticated());
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults()); // [!code --]
        return http.build();
    }
```

我们也可以将指定过滤器禁用

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
                requests.anyRequest().authenticated());
        http.formLogin(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable); // [!code ++]
        return http.build();
    }
```

> [!CAUTION] 注意
>
> http.csrf().disable() 自 Spring Security 6.1 开始已被标记为过时

我们还可以指定相干 URL 让其跳过 Spring Security 过滤器链的检测

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/api/users/**").permitAll()); // [!code ++]
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        http.formLogin(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
```

![image-20240820213928055](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408202139236.png)

我们可以将上面的代码优化格式（通过链式调用的方法）

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests. // [!code focus:5]
                        requestMatchers("/api/users/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
```

