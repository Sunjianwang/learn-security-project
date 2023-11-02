package demo.userdetail;

import demo.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
public class DemoUserDetailService implements UserDetailsService {
    @Resource
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userMapper
                .queryUserByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户名错误"));
    }
}
