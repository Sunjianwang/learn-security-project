package learn.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import learn.config.AppProperties;
import learn.util.CollectionUtil;
import learn.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Jwt过滤器
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Component
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    @Resource
    private AppProperties appProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(checkJwtToken(request)){
            validateToken(request)
                    .filter(claims -> claims.get("authorities") != null)
                    .ifPresent(claims -> {
                                //获取authority列表
                                List<?> list = CollectionUtil.convertObjectToList(claims.get("authorities"));
                                //构建SimpleGrantedAuthority列表
                                List<SimpleGrantedAuthority> grantedAuthorityList = list.stream().map(String::valueOf).map(s -> new SimpleGrantedAuthority(s)).collect(Collectors.toList());
                                //构建UsernamePasswordAuthenticationToken
                                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, grantedAuthorityList);
                                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                            }
                    );
        }else {
            SecurityContextHolder.clearContext();
        }
        doFilter(request, response, filterChain);
    }

    /**
     * 解析TOKEN
     * @param request
     * @return
     */
    private Optional<Claims> validateToken(HttpServletRequest request){
        String token = request.getHeader(appProperties.getJwt().getHeader()).replace(appProperties.getJwt().getPrefix(), "");
        try {
            return Optional.of(Jwts.parser().verifyWith(JwtUtil.accessKey).build().parseSignedClaims(token).getPayload());
        }catch (Exception e){
            log.error("", e);
            return Optional.empty();
        }
    }

    /**
     * 检查JWT TOKEN 是否在Header中
     * @param request
     * @return
     */
    private boolean checkJwtToken(HttpServletRequest request) {
        String requestHeader = request.getHeader(appProperties.getJwt().getHeader());
        return requestHeader != null && requestHeader.startsWith(appProperties.getJwt().getPrefix());
    }
}
