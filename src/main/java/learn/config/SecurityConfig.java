package learn.config;

import learn.filter.JwtFilter;
import learn.filter.RestAuthenticationFilter;
import learn.handler.LoginFailureHandler;
import learn.handler.LoginSuccessHandler;
import learn.userdetail.LearnUserDetail;
import learn.userdetail.LearnUserDetailsPassword;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 安全配置
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfig{

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtFilter jwtFilter;
    private final PasswordEncoder passwordEncoder;
    private final LearnUserDetailsPassword userDetailsPasswordService;
    private final LearnUserDetail userDetail;

    /**
     * 在Spring Security5.7.0-M2之后，使用此方法进行Http安全配置
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(99)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .mvcMatchers("/auth/**").permitAll()
                        .mvcMatchers("/admin/**").hasRole("ADMIN")
                        .mvcMatchers("/user/users/{username}/**").access("@userService.checkCurrentUserName(authentication, #username)")
                        //URL配置是有顺序的，越具体的放在越前面，越笼统的放在越后面，如果/user/**放在/user/users/**前，那不会进行后面的权限控制
                        .mvcMatchers("/user/**").hasRole("USER")
                        .anyRequest().denyAll())
                .addFilterAfter(initRestAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                //添加JWT过滤器
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults()).build();
    }

    /**
     * 配置AuthenticationManager，在Spring Security5.7.0-M2之后使用@Autowired自动注入
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetail)
                .passwordEncoder(passwordEncoder)
                .userDetailsPasswordManager(userDetailsPasswordService); // 配置密码自动升级服务
    }

    /**
     * 在Spring Security5.7.0-M2之后，使用此方法进行Web安全配置
     * @return
     * @throws Exception
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() throws Exception {
        return
                //使某些资源不进行过滤器过滤
                web -> web.ignoring().mvcMatchers("/public/**", "/error")
                //放行静态资源
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * 默认用户信息配置，生产环境禁用
     * @return
     */
//    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123456")
                .roles("USER", "ADMIN").build();
        return new InMemoryUserDetailsManager(user);
    }

    private RestAuthenticationFilter initRestAuthenticationFilter() throws Exception {
        RestAuthenticationFilter restAuthenticationFilter = new RestAuthenticationFilter();
        restAuthenticationFilter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
        restAuthenticationFilter.setAuthenticationFailureHandler(new LoginFailureHandler());
        restAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        return restAuthenticationFilter;
    }
}
