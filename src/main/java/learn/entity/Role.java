package learn.entity;

import lombok.Data;

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
public class Role implements Serializable {

    private String id;

    private String roleName;

    private String displayName;

    private Set<Permission> permissions = new HashSet<>();

    private Set<User> users;
}
