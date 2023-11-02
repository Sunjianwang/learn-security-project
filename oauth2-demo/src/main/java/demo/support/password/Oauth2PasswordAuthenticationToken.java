package demo.support.password;

import jodd.util.CollectionUtil;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
public class Oauth2PasswordAuthenticationToken extends AbstractAuthenticationToken {

    @Getter
    private final AuthorizationGrantType authorizationGrantType;
    private final Authentication clientPrincipal;
    @Getter
    private final Set<String> scopes;
    @Getter
    private final Map<String, Object> additionalParameters;

    public Oauth2PasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                             Authentication clientPrincipal,
                                             Set<String> scopes,
                                             Map<String, Object> additionalParameters) {
        super(Collections.EMPTY_LIST);
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.scopes = scopes;
        this.additionalParameters = additionalParameters;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }
}
