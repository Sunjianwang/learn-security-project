package demo.entity;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.HashMap;
import java.util.Map;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
public class Oauth2User extends User implements OAuth2AuthenticatedPrincipal {

    private Map<String, Object> attributes = new HashMap<>();

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
}
