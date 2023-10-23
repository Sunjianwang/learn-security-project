package learn.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
public class UserService {

    public boolean checkCurrentUserName(Authentication authentication, String username){
        return authentication.getName().equals(username);
    }
}
