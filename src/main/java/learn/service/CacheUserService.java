package learn.service;

import learn.entity.User;
import learn.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

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
        String mfaId = user.getMfaKey();
        log.debug("mfaId:{}", mfaId);
        RMapCache<String, User> mapCache = redisson.getMapCache("mfaCache");
        if (!mapCache.containsKey(mfaId)){
            mapCache.put(mfaId, user, totpUtil.getTimeTemp(), TimeUnit.SECONDS);
        }
        return mfaId;
    }

}
