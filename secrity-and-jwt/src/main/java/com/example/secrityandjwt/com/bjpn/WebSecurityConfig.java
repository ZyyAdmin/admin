package com.example.secrityandjwt.com.bjpn;



import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.PrintWriter;
import java.util.*;
import java.util.stream.Collectors;


@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //设置内存用户模拟
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(passwordEncoder().encode("123"))
                .authorities("sys:add","sys:query");
    }




    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //关闭跨域请求
        http.csrf().disable();
        //这里关闭session
        http.sessionManagement().disable();
        //配置登录
        http.formLogin()
                .loginProcessingUrl("/mylogin")//登录接口
                .successHandler(loginSuccessHandler())//登录成功之后处理
                .failureHandler(loginFailureHandler()).permitAll();
        http.authorizeRequests().anyRequest().authenticated();
    }
    @Bean
    public AuthenticationFailureHandler loginFailureHandler(){
        return (request,response,exception)->{
          //  response.setContentType("application/json;charset=utf-8");
            HashMap<String,Object> map = new HashMap<>();
            map.put("code",401);
            map.put("msg","用户名密码错误");
//            ObjectMapper objectMapper = new ObjectMapper();
//            String string = objectMapper.writeValueAsString(map);
//            PrintWriter writer = response.getWriter();
//            writer.write(string);
//            writer.flush();
//            writer.close();
        };
    }

    //登陆成功访问处理器,登陆成功之后我们生成jwt，存储到redis中去
    @Bean
    public  AuthenticationSuccessHandler loginSuccessHandler() {
        return (request,response,authentication)->{
            //拿到用户名,这里可以转成自己封装的用户对象
//            User user = (User) authentication.getPrincipal();
//            String username = user.getUsername();

            //拿到权限，转成string集合放在jwt中
            List<String> collect = authentication
                    .getAuthorities()
                    .stream()
                    .map(Objects::toString)
                    .collect(Collectors.toList());

            HashMap<String,Object> header = new HashMap<>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");
            //设置颁发时间
            Date createTime = new Date();

            //设置过期时间
            Calendar instance = Calendar.getInstance();
            instance.add(Calendar.SECOND,7200);//设置2个小时以后时间
            Date expireTime = instance.getTime();

//            String jwt = JWT.create()
//                    .withHeader(header)
//                    .withClaim("username",username)
//                    .withClaim("auths",collect)
//                    .withIssuedAt(createTime)//设置颁发时间
//                    .withExpiresAt(expireTime)
//                    .withSubject("subject")
//                    .sign(Algorithm.HMAC256("jwt-powernode")); //jwt-powernode等于是要是，只有我们服务端知道,设置签名秘钥
//
//            HashMap<String,Object> map = new HashMap<>();
//            map.put("code",200);
//            map.put("token",jwt);
//            map.put("expireTime",expireTime);
//            ObjectMapper objectMapper = new ObjectMapper();
//            String string = objectMapper.writeValueAsString(map);
//            PrintWriter writer = response.getWriter();
//            writer.write(string);
//            writer.flush();
//            writer.close();

        };
    }



    @Bean
    /**
     * 从spring5之后，强制要求密码加密
     * 配置一个spring匹配器
     * 当然我们也可以不加密，
     * 但是官方要求是不管你是否加密，
     * 都必须配置一个类似Shiro的凭证匹配器
     */
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }
}
