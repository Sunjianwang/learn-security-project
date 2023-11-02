package learn.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * 自定义AuthenticationFilter
 *
 * @author Sunjianwang
 * @version 1.0
 */
public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper;

    //只对指定路径进行拦截匹配
    private final static AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/login", "POST");
    protected AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    public RestAuthenticationFilter(ObjectMapper objectMapper){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //账号密码认证Token
        UsernamePasswordAuthenticationToken authenticationToken;
        //获取账号密码
        try {
            InputStream inputStream = request.getInputStream();
            JsonNode jsonNode = objectMapper.readTree(inputStream);
            String username = jsonNode.get("username").textValue();
            String password = jsonNode.get("password").textValue();

            authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
        } catch (IOException e) {
            throw new BadCredentialsException("用户名或密码错误");
        }
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }
}
