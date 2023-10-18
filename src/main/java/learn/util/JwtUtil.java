package learn.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import learn.config.AppProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * JWT工具类
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Component
@Slf4j
public class JwtUtil {

    private static final String accessKeyString = "a5d19d881162e2a5341f352686fa3dddd0f57b687e846e1d36675f417adeff9854db116144b3d993393711c926b2badd9b49dd882492bdeb6456d725766aacf8";

    private static final String refreshKeyString = "6e920ea5e1f07a5e31ec5a19d0654b9c30c955670787feb244b2517995f4ddacf14f467ac28efc67a15395154ea9ea0303e8874cc11613872890ddcc84f1668c";

    /**
     * 用于访问令牌的密钥
     */
    public static final SecretKey accessKey = Keys.hmacShaKeyFor(accessKeyString.getBytes());

    /**
     * 用于刷新令牌的密钥
     */
    public static final SecretKey refreshKey = Keys.hmacShaKeyFor(refreshKeyString.getBytes());

    @Resource
    private AppProperties appProperties;

    /**
     * 根据刷新令牌获取访问令牌
     * @param refreshToken
     * @return
     */
    public String createAccessTokenByRefreshToken(String refreshToken){
        return getClaimsByToken(refreshToken)
                .map(claims -> Jwts.builder()
                        .id("learn")
                        .claims(claims)
                        .issuedAt(new Date())
                        .expiration(new Date(System.currentTimeMillis() + appProperties.getJwt().getRefreshTokenExpireTime()))
                        .signWith(accessKey, Jwts.SIG.HS512)
                        .compact()).orElseThrow(() -> new AccessDeniedException("拒绝访问"));
    }

    /**
     * 根据令牌获取Claims
     * @param token
     * @return
     */
    private Optional<Claims> getClaimsByToken(String token){
        try {
            return Optional.of(Jwts.parser().verifyWith(refreshKey).build().parseSignedClaims(token).getPayload());
        }catch (Exception e){
            return Optional.empty();
        }
    }

    /**
     * 验证访问令牌是否合法，不要求进行过期验证
     * @param token 令牌
     * @return
     */
    public boolean validAccessTokenWithOutExpireTime(String token){
        return validTokenWithExpireTime(token, accessKey, false);
    }

    /**
     * 验证访问令牌是否合法，要求进行过期验证
     * @param token 令牌
     * @return
     */
    public boolean validAccessTokenWithExpireTime(String token){
        return validTokenWithExpireTime(token, accessKey, true);
    }

    /**
     * 验证刷新令牌是否合法，要求进行过期验证
     * @param refreshToken 令牌
     * @return
     */
    public boolean validRefreshTokenWithExpireTime(String refreshToken){
        return validTokenWithExpireTime(refreshToken, refreshKey, true);
    }

    /**
     * 验证令牌是否合法
     * @param token 令牌
     * @param key 密钥
     * @param isWithExpireTime 是否进行过期验证
     * @return
     */
    private boolean validTokenWithExpireTime(String token, SecretKey key, boolean isWithExpireTime){
        try{
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        }catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            //解析令牌出错过期且要求不能过期
            if (e instanceof ExpiredJwtException){
                return !isWithExpireTime;
            }
            return false;
        }
    }

    /**
     * 创建访问令牌
     * @param userDetails
     * @return
     */
    public String accessToken(UserDetails userDetails){
        return createJwtToken(userDetails, accessKey, appProperties.getJwt().getAccessTokenExpireTime());
    }

    /**
     * 创建刷新令牌
     * @param userDetails
     * @return
     */
    public String refreshToken(UserDetails userDetails){
        return createJwtToken(userDetails, refreshKey, appProperties.getJwt().getRefreshTokenExpireTime());
    }

    /**
     * 生成令牌
     * @param userDetails
     * @param key
     * @param timeToExpire
     * @return
     */
    private String createJwtToken(UserDetails userDetails, SecretKey key, long timeToExpire){

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
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }
}
