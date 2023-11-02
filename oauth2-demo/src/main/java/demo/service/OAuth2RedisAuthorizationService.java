package demo.service;

import lombok.RequiredArgsConstructor;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * 自定义redis认证服务
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
public class OAuth2RedisAuthorizationService implements OAuth2AuthorizationService {

    private final RedissonClient redissonClient;
    private final String ACCESS_TOKEN = "access_token";
    private final String REFRESH_TOKEN = "refresh_token";

    @Override
    public void save(OAuth2Authorization authorization) {
        RMapCache<Object, Object> tokens = redissonClient.getMapCache("tokens");
        //保存访问令牌
        if (!ObjectUtils.isEmpty(authorization.getAccessToken())){
            tokens.put(formatKey(ACCESS_TOKEN, authorization.getAccessToken().getToken().getTokenValue()),
                    authorization,
                    Duration.ofMinutes(5).getSeconds(),
                    TimeUnit.SECONDS);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        RMapCache<Object, Object> tokens = redissonClient.getMapCache("tokens");
        //保存访问令牌
        if (!ObjectUtils.isEmpty(authorization.getAccessToken())){
            tokens.remove(formatKey(ACCESS_TOKEN, authorization.getAccessToken().getToken().getTokenValue()));
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.notNull(token, "token must be not null");
        Assert.notNull(tokenType, "tokenType must be not null");
        RMapCache<Object, Object> tokens = redissonClient.getMapCache("tokens");
        if (tokens.containsValue(formatKey(tokenType.getValue(), token))){
            return (OAuth2Authorization) tokens.get(formatKey(tokenType.getValue(), token));
        }
        return null;
    }

    private String formatKey(String tokenType, String token){
        return String.format("%s::%s", tokenType, token);
    }
}
