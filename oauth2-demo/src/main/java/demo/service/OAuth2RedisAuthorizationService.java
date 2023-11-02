package demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
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

    private final RedisTemplate<String,Object> redisTemplate;
    private final String ACCESS_TOKEN = "access_token";
    private final String REFRESH_TOKEN = "refresh_token";

    @Override
    public void save(OAuth2Authorization authorization) {
        //保存访问令牌
        if (!ObjectUtils.isEmpty(authorization.getAccessToken())){
            redisTemplate.opsForValue().set(formatKey(ACCESS_TOKEN, authorization.getAccessToken().getToken().getTokenValue()),
                    authorization,
                    Duration.ofMinutes(5).getSeconds(),
                    TimeUnit.SECONDS);
        }
        //保存刷新令牌
        if (!ObjectUtils.isEmpty(authorization.getRefreshToken())){
            redisTemplate.opsForValue().set(formatKey(REFRESH_TOKEN, authorization.getAccessToken().getToken().getTokenValue()),
                    authorization,
                    Duration.ofMinutes(5).getSeconds(),
                    TimeUnit.SECONDS);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        //删除访问令牌
        if (!ObjectUtils.isEmpty(authorization.getAccessToken())){
            redisTemplate.delete(formatKey(ACCESS_TOKEN, authorization.getAccessToken().getToken().getTokenValue()));
        }
        //删除刷新令牌
        if (!ObjectUtils.isEmpty(authorization.getRefreshToken())){
            redisTemplate.delete(formatKey(REFRESH_TOKEN, authorization.getAccessToken().getToken().getTokenValue()));
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
        return (OAuth2Authorization) redisTemplate.opsForValue().get(formatKey(tokenType.getValue(), token));
    }

    private String formatKey(String tokenType, String token){
        return String.format("%s::%s", tokenType, token);
    }
}
