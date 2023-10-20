package learn.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@NoArgsConstructor
@AllArgsConstructor
@Builder
@With
@Data
public class User implements UserDetails, Serializable {

    private String id;
    private String username;
    private String password;
    private String email;
    private String name;
    private Boolean usingMfa;
    private String mfaKey;
    private Set<Role> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
