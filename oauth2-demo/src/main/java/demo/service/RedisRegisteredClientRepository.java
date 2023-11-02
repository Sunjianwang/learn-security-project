package demo.service;

import lombok.RequiredArgsConstructor;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.function.Consumer;

/**
 * 客户端注册库，目前采用配置文件方式，可改为数据库
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RequiredArgsConstructor
@Service
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2ClientProperties clientProperties;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String id) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        List<ClientRegistration> clientRegistrationList = new ArrayList<>(OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(clientProperties).values());
        ClientRegistration clientRegistration = clientRegistrationList.stream()
                .filter(client -> client.getClientId().equals(clientId))
                .findFirst()
                .orElseThrow(() -> new OAuth2AuthenticationException("请求客户端异常"));

        return RegisteredClient.withId(clientRegistration.getClientId())
                .clientId(clientRegistration.getClientId())
                .clientSecret("{noop}" + clientRegistration.getClientSecret())
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(stringToSetCollection(clientRegistration.getAuthorizationGrantType().getValue())))
                .scopes(scopes -> scopes.addAll(clientRegistration.getScopes()))
                .clientAuthenticationMethods(clientAuthenticationMethod -> {
                    clientAuthenticationMethod.add(clientRegistration.getClientAuthenticationMethod());
                }).build();
    }

    private Set<AuthorizationGrantType> stringToSetCollection(String string){
        String[] grantTypes = StringUtils.split(string, ",");
        Assert.notNull(grantTypes, "认证类型集合为空");
        Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        for (String grantType:
             grantTypes) {
            authorizationGrantTypes.add(new AuthorizationGrantType(grantType));
        }
        return authorizationGrantTypes;
    }
}
