package learn.service;

import learn.entity.User;
import learn.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CacheUserService {

    private final RedissonClient redisson;
    private final TotpUtil totpUtil;

    public String catchUser(User user){
        //保存User信息时需要把mfaKey字段进行Base64处理
        String mfaId = user.getMfaKey();
        log.debug("mfaId:{}", mfaId);
        RMapCache<String, User> mapCache = redisson.getMapCache("mfaCache");
        if (!mapCache.containsKey(mfaId)){
            mapCache.put(mfaId, user, totpUtil.getTimeTemp(), TimeUnit.SECONDS);
        }
        return mfaId;
    }

    public Optional<User> verifyTotp(String mfaId, String code) throws InvalidKeyException {
        RMapCache<String, User> mfaCache = redisson.getMapCache("mfaCache");
        if (!mfaCache.containsKey(mfaId)){
            return Optional.empty();
        }
        User userCache = mfaCache.get(mfaId);
        try {
            if (totpUtil.verifyTotp(totpUtil.decodeStringToKey(mfaId), code)){
                mfaCache.remove(mfaId);
                log.debug("二次验证成功！");
                return Optional.of(userCache);
            }else {
                log.debug("二次验证失败！验证码不正确");
                return Optional.empty();
            }
        }catch (InvalidKeyException e){
            e.printStackTrace();
            log.debug("二次验证失败！");
            return Optional.of(userCache);
        }
    }
}
