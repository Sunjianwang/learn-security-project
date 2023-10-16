package learn.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Data
public class Role implements GrantedAuthority, Serializable {

    private String id;

    private String roleName;

    @Override
    public String getAuthority() {
        return roleName;
    }
}
