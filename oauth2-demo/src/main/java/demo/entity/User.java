package demo.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

    @JsonIgnore
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .flatMap(role -> Stream.concat(Stream.of(new SimpleGrantedAuthority(role.getRoleName())), role.getPermissions().stream()))
                .collect(Collectors.toList());
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
