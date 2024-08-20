# 第一个 SpringSecurity 程序

> [!NOTE] 内容
>
> - Spring Security 概述
> - 认证、授权相关概念
> - 快速入门

# 一、什么是 Spring Security

Spring Security 是一个 Java 框架，用于保护应用程序的安全性。它提供了一套全面的安全解决方案，包括身份验证、授权、防止攻击等功能。Spring Security 基于过滤器链的概念，可以轻松地集成到任何基于 Spring 的应用程序中。它支持多种身份验证选项和授权策略，开发人员可以根据需要选择适合的方式。此外，Spring Security 还提供了一些附加功能，如集成第三方身份验证提供商和单点登录，以及会话管理和密码编码等。总之，Spring Security 是一个强大且易于使用的框架，可以帮助开发人员提高应用程序的安全性和可靠性。

Spring Security是一个框架，提供 [认证（authentication）](https://springdoc.cn/spring-security/features/authentication/index.html)、[授权（authorization）](https://springdoc.cn/spring-security/features/authorization/index.html) 和 [保护，以抵御常见的攻击](https://springdoc.cn/spring-security/features/exploits/index.html)。它对保护命令式和响应式应用程序有一流的支持，是保护基于Spring的应用程序的事实标准。

---

官网介绍

> - 英文：Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.
>
> - 中文：Spring Security 是一个功能强大、高度可定制的身份验证和访问控制框架。它是确保基于 Spring 的应用程序安全的事实标准。

---

> - 英文：Spring Security is a framework that focuses on providing both authentication and authorization to Java applications. Like all Spring projects, the real power of Spring Security is found in how easily it can be extended to meet custom requirements
> - 中文：Spring Security 是一个专注于为 Java 应用程序提供身份验证和授权的框架。与所有 Spring 项目一样，Spring Security 的真正威力在于它可以轻松扩展以满足自定义需求

- [官方文档（英文）](https://spring.io/projects/spring-security)

![image-20240820161151113](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201611216.png)

- [社区文档 （社区）](https://springdoc.cn/spring-security/)

![image-20240820161201891](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201612987.png)

Spring Security 支持以下几点特性：

| 英文                                                         | 中文                                       |
| ------------------------------------------------------------ | ------------------------------------------ |
| Comprehensive and extensible support for both Authentication and Authorization | 为身份验证和授权提供全面、可扩展的支持     |
| Protection against attacks like session fixation, clickjacking, cross site request forgery, etc | 防止会话固定、点击劫持、跨站请求伪造等攻击 |
| Servlet API integration                                      | 集成 Servlet API                           |
| Optional integration with Spring Web MVC                     | 可选择与 Spring Web MVC 集成               |

# 二、什么是认证

Spring Security 提供了对 [认证（Authentication）](https://en.wikipedia.org/wiki/Authentication) 的全面支持。**认证是指我们如何验证试图访问特定资源的人的身份**。一个常见的验证用户的方法是要求用户输入用户名和密码。一旦进行了认证，我们就知道了身份并可以执行授权。

与认证方面相关的 HTTP 响应码：`401 Unatuthorized`

# 三、什么是授权

Spring Security 为 [授权 （Authorization ）](https://en.wikipedia.org/wiki/Authorization) 提供全面支持。**授权是指确定允许谁访问特定资源**。Spring Security 允许基于请求的授权和基于方法的授权，从而提供 [深度防御](https://en.wikipedia.org/wiki/Defense_in_depth_(computing))。

与授权方面相关的 HTTP 响应码：`403 Forbidden`

# 四、快速入门

> [!TIP] 先决条件
>
> Spring Security 要求有 Java 8 或更高的运行环境。由于 Spring Security 旨在以独立的方式运行，你不需要在你的 Java 运行时环境中放置任何特殊的配置文件。特别是，你不需要配置一个特殊的 Java 认证和授权服务（JAAS）策略文件，也不需要把 Spring Security 放到普通的 classpath 位置。
>
> 同样地，如果你使用 EJB 容器或 Servlet 容器，你不需要把任何特殊的配置文件放在任何地方，也不需要把 Spring Security 包含在服务器的 classloader 中。所有需要的文件都包含在你的应用程序中。
>
> 这种设计提供了最大的部署时间灵活性，因为你可以将你的目标工件（无论是 JAR、WAR 还是 EAR）从一个系统复制到另一个系统，并立即运行。

本处采用：

|                         TOOLS                         |                    VERSION                    |
| :---------------------------------------------------: | :-------------------------------------------: |
| IntelliJ IDEA  (Ultimate Edition) \| Maven \| OpenJDK | 2024.2.0.1 \| 3.9.8 \| 17.0.11 2024-04-16 LTS |
|            Spring Boot \| Spring Security             |                3.1.7 \| 6.1.6                 |


1. 创建工程

![image-20240820162633647](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201626525.png)

2. 引入依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

3. 创建相关包并添加测试资源

![image-20240820162808772](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201628876.png)

添加测试资源

```java
@Controller
@RequestMapping("/api/users")
public class UserController {

    @ResponseBody
    @GetMapping("sayHello")
    public String sayHello() {
        return "hello";
    }
}
```

4. 启动并测试

访问 `http://localhost:8080/api/users/sayHello` 出现下面界面

![image-20240820163557012](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201635108.png)

这时候我们的应用程序就被 Spring Security 保护了

> [!TIP] 这个时候我们可以思考以下问题：
>
> 1. 账号、密码是什么呢可以自定义吗
> 2. 这个登录页面是从哪里来的呢
>
> 下面我们将依次探究上述问题

关于上述 账号密码是什么的问题 我们打开 IDEA 控制台发现 Spring Boot 启动日志中打印出

```sh
Using generated security password: 4d60ab17-9534-49ef-9b8b-aab78068cd99

This generated password is for development use only. Your security configuration must be updated before running your application in production.
```

![image-20240820163314501](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201633613.png)

根据提示我们可以得知默认生成的密码为 `4d60ab17-9534-49ef-9b8b-aab78068cd99` 但此处没有用户名相关信息（默认情况下用户名为 `user`）接下来我们使用上述信息进行登录

![image-20240820164052434](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201640531.png)

可以看到我们已经访问成功了，接下来我们探究 用户名和密码可以自定义吗这个问题，答案是可以的我们可以通过配置文件的方式为我们的程序配置指定的用户名和密码

```yaml
spring:
  security:
    user:
      name: root
      password: root
```

配置好后我们重启服务器（此时默认生成的密码已经不再打印了，因为我们已经配置了指定的用户信息）

![image-20240820165030956](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201650065.png)

继续访问 `http://localhost:8080/api/users/sayHello` 输入 root + root

![image-20240820165135506](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201651616.png)

可以看到成功访问，此时我们已经实现了如何自定义用户名和密码，接下来让我们来探究第二个问题，这个登陆页面是从哪里来的呢

既然我们是通过 starter 的方式引入的 Spring Security 那么我们可以通过 AutoConfiguration 来观察下引入 Spring Security 后我们引入了那些组件

![image-20240820165512240](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201655374.png)

该类代码如下：

```java
@AutoConfiguration(before = UserDetailsServiceAutoConfiguration.class)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties(SecurityProperties.class)
@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })
public class SecurityAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(AuthenticationEventPublisher.class)
	public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
		return new DefaultAuthenticationEventPublisher(publisher);
	}

}
```

其中我们重点关注 `@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })` 中的 `SpringBootWebSecurityConfiguration` 类，点击查看

```java
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = Type.SERVLET)
class SpringBootWebSecurityConfiguration {

	/**
	 * The default configuration for web security. It relies on Spring Security's
	 * content-negotiation strategy to determine what sort of authentication to use. If
	 * the user specifies their own {@link SecurityFilterChain} bean, this will back-off
	 * completely and the users should specify all the bits that they want to configure as
	 * part of the custom security configuration.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnDefaultWebSecurity
	static class SecurityFilterChainConfiguration {

		@Bean
		@Order(SecurityProperties.BASIC_AUTH_ORDER)
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
			http.formLogin(withDefaults());
			http.httpBasic(withDefaults());
			return http.build();
		}

	}

    //...

}
```

注意到该类中有一个名为 `SecurityFilterChainConfiguration` 的静态方法，下面我们给出注释的翻译

```sh
Web 安全性的默认配置。它依赖于 Spring Security 的内容协商策略来确定要使用的身份验证类型
如果用户指定了自己的 SecurityFilterChain bean，这将完全退出
用户应指定他们想要配置的所有位，作为自定义安全配置的一部分。
```

结合注释不难得出，该类主要用于进行默认安全配置，且方法名中的 Filter 表明该类大概率和过滤器有关，下面我们重点关注该类的方法参数和方法体：

- 方法参数：`HttpSecurity http` 它允许为特定的 http 请求配置基于 Web 的安全性

- 方法体：

  - `http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated()); `不难看出该代码主要用于配置需要拦截的资源 `requests ` 其中 `requests.anyRequest().authenticated()` 表示所有资源都需要进行认证

  - `http.formLogin(withDefaults());` 采用默认方式配置 `formLogin`

  - `http.httpBasic(withDefaults());` 采用默认方式配置 `httpBasic`


- 返回值：通过 `http.build()` 构造一个 `SecurityFilterChain ` 后返回

# 五、其它 Java 安全框架

1. **[Apache Shiro](https://shiro.apache.org/)**：
   - **简介**：Apache Shiro 是一个强大且灵活的开源安全框架，用于身份验证、授权、会话管理、加密和缓存。
   - **特点：**
     - 简单易用，易于集成。
     - 支持多种身份验证方式，如用户名/密码、LDAP、OAuth、OpenID等。
     - 支持细粒度的权限控制。
     - 支持分布式会话管理。
   - **应用场景**：适用于需要简单安全解决方案的项目。

2. **[Sa-Token](https://sa-token.cc/index.html)**
   - **简介：** **Sa-Token** 是一个轻量级 Java 权限认证框架，主要解决：**登录认证**、**权限认证**、**单点登录**、**OAuth2.0**、**分布式Session会话**、**微服务网关鉴权** 等一系列权限相关问题。
   - **特点：**
     - **登录认证** —— 单端登录、多端登录、同端互斥登录、七天内免登录。
     - **权限认证** —— 权限认证、角色认证、会话二级认证。
     - **踢人下线** —— 根据账号id踢人下线、根据Token值踢人下线。
     - **注解式鉴权** —— 优雅的将鉴权与业务代码分离。
     - **路由拦截式鉴权** —— 根据路由拦截鉴权，可适配 restful 模式。
     - **Session会话** —— 全端共享Session,单端独享Session,自定义Session,方便的存取值。
     - **持久层扩展** —— 可集成 Redis，重启数据不丢失。
     - **前后台分离** —— APP、小程序等不支持 Cookie 的终端也可以轻松鉴权。
     - **Token风格定制** —— 内置六种 Token 风格，还可：自定义 Token 生成策略。
     - **记住我模式** —— 适配 [记住我] 模式，重启浏览器免验证。
     - **二级认证** —— 在已登录的基础上再次认证，保证安全性。
     - **模拟他人账号** —— 实时操作任意用户状态数据。
     - **临时身份切换** —— 将会话身份临时切换为其它账号。
     - **同端互斥登录** —— 像QQ一样手机电脑同时在线，但是两个手机上互斥登录。
     - **账号封禁** —— 登录封禁、按照业务分类封禁、按照处罚阶梯封禁。
     - **密码加密** —— 提供基础加密算法，可快速 MD5、SHA1、SHA256、AES 加密。
     - **会话查询** —— 提供方便灵活的会话查询接口。
     - **Http Basic认证** —— 一行代码接入 Http Basic、Digest 认证。
     - **全局侦听器** —— 在用户登陆、注销、被踢下线等关键性操作时进行一些AOP操作。
     - **全局过滤器** —— 方便的处理跨域，全局设置安全响应头等操作。
     - **多账号体系认证** —— 一个系统多套账号分开鉴权（比如商城的 User 表和 Admin 表）
     - **单点登录** —— 内置三种单点登录模式：同域、跨域、同Redis、跨Redis、前后端分离等架构都可以搞定。
     - **单点注销** —— 任意子系统内发起注销，即可全端下线。
     - **OAuth2.0认证** —— 轻松搭建 OAuth2.0 服务，支持openid模式 。
     - **分布式会话** —— 提供共享数据中心分布式会话方案。
     - **微服务网关鉴权** —— 适配Gateway、ShenYu、Zuul等常见网关的路由拦截认证。
     - **RPC调用鉴权** —— 网关转发鉴权，RPC调用鉴权，让服务调用不再裸奔
     - **临时Token认证** —— 解决短时间的 Token 授权问题。
     - **独立Redis** —— 将权限缓存与业务缓存分离。
     - **Quick快速登录认证** —— 为项目零代码注入一个登录页面。
     - **标签方言** —— 提供 Thymeleaf 标签方言集成包，提供 beetl 集成示例。
     - **jwt集成** —— 提供三种模式的 jwt 集成方案，提供 token 扩展参数能力。
     - **RPC调用状态传递** —— 提供 dubbo、grpc 等集成包，在RPC调用时登录状态不丢失。
     - **参数签名** —— 提供跨系统API调用签名校验模块，防参数篡改，防请求重放。
     - **自动续签** —— 提供两种Token过期策略，灵活搭配使用，还可自动续签。
     - **开箱即用** —— 提供SpringMVC、WebFlux、Solon 等常见框架集成包，开箱即用。
     - **最新技术栈** —— 适配最新技术栈：支持 SpringBoot 3.x，jdk 17。

![image-20240820170907068](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201709250.png)

![image-20240820170851602](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201708719.png)
