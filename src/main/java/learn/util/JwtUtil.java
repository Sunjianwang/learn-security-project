package learn.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import learn.config.AppProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * JWT工具类
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Component
public class JwtUtil {

    //用于访问令牌的密钥
    private Key key = Jwts.SIG.HS512.key().build();

    //用于刷新令牌的密钥
    private Key refreshKey = Jwts.SIG.HS512.key().build();

    @Resource
    private AppProperties appProperties;

    public String refreshToken(UserDetails userDetails){
        return createJwtToken(userDetails, refreshKey, appProperties.getJwt().getRefreshTokenExpireTime());
    }

    public String accessToken(UserDetails userDetails){
        return createJwtToken(userDetails, key, appProperties.getJwt().getAccessTokenExpireTime());
    }

    public String createJwtToken(UserDetails userDetails, Key key, long timeToExpire){

        long issueTime = System.currentTimeMillis();
        return Jwts.builder()
                .id("learn")
                //声明
                .claim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                //主题
                .subject(userDetails.getUsername())
                //签发时间
                .issuedAt(new Date(issueTime))
                .expiration(new Date(issueTime + timeToExpire))
                .signWith(key)
                .compact();
    }
}
