package learn.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Data
public class Permission implements GrantedAuthority, Serializable {

    private String id;
    private String authority;
    private String displayName;
    private Set<Role> roleSet = new HashSet<>();
}
