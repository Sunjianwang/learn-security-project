package demo.service;

import demo.entity.Oauth2User;
import demo.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.ObjectUtils;

import java.security.Principal;

/**
 * 自定义Token内省规则
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RequiredArgsConstructor
public class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OAuth2RedisAuthorizationService authorizationService;

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (ObjectUtils.isEmpty(authorization)){
            throw new InvalidBearerTokenException("非法Token");
        }
        UsernamePasswordAuthenticationToken authenticationToken = authorization.getAttribute(Principal.class.getName());
        if (ObjectUtils.isEmpty(authenticationToken)){
            throw new AccessDeniedException("用户未认证");
        }
        User principal = (User) authenticationToken.getPrincipal();
        Oauth2User oauth2User = new Oauth2User();
        BeanUtils.copyProperties(principal, oauth2User);
        return oauth2User;
    }
}
