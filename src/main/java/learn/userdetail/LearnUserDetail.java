package learn.userdetail;

import learn.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Optional;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
public class LearnUserDetail implements UserDetailsService {

    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return Optional.of(userMapper.queryUserByUserName(username))
                .orElseThrow(() -> new UsernameNotFoundException(username + "用户未找到"));
    }
}
