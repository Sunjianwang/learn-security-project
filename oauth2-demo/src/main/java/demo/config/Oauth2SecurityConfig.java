package demo.config;

import demo.service.OAuth2CustomTokenGenerator;
import demo.service.OAuth2RedisAuthorizationService;
import demo.support.password.Oauth2PasswordAuthenticationConverter;
import demo.support.password.Oauth2PasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Arrays;

/**
 * Oauth2认证服务器配置
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
@Slf4j
@RequiredArgsConstructor
public class Oauth2SecurityConfig {

    private final OAuth2RedisAuthorizationService redisAuthorizationService;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain oauth2FilterChain(HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        httpSecurity.apply(authorizationServerConfigurer.tokenEndpoint(tokenEndPoint -> {
            tokenEndPoint.accessTokenRequestConverter(customAuthenticationConverter());
        }));

        DefaultSecurityFilterChain securityFilterChain = httpSecurity
                .apply(authorizationServerConfigurer.authorizationService(redisAuthorizationService)
                        .authorizationServerSettings(AuthorizationServerSettings.builder().build()))
                .and()
                .authorizeRequests()
                .mvcMatchers("/oauth2/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)
                .build();
        ;

        addCustomOauth2GrantAuthenticationProvider(httpSecurity);

        return securityFilterChain;

    }

    /**
     * 自定义令牌生成
     * @return
     */
    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(){
        return new DelegatingOAuth2TokenGenerator(new OAuth2CustomTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }

    /**
     * 自定义授权方式
     *
     * @return
     */
    private AuthenticationConverter customAuthenticationConverter(){
        return new DelegatingAuthenticationConverter(Arrays.asList(
                new Oauth2PasswordAuthenticationConverter()
        ));
    }

    private void addCustomOauth2GrantAuthenticationProvider(HttpSecurity httpSecurity){
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);

        httpSecurity.authenticationProvider(new Oauth2PasswordAuthenticationProvider(authenticationManager, authorizationService, tokenGenerator()));
    }
}
