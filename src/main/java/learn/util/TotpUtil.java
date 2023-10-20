package learn.util;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TotpUtil {

    private static final long TIME_TEMP = 60 * 5L;

    private static final int PASSWORD_LENGTH = 6;

    private KeyGenerator keyGenerator;

    private TimeBasedOneTimePasswordGenerator totp;

    {
        try {
            totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(TIME_TEMP), PASSWORD_LENGTH);
            keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
            keyGenerator.init(512);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            log.error("没有找到算法{}", e.getLocalizedMessage());
        }
    }

    /**
     * 生成一次性验证码
     * @param key
     * @param time
     * @return
     * @throws InvalidKeyException
     */
    public String createTotp(Key key, Instant time) throws InvalidKeyException {
        int password = totp.generateOneTimePassword(key, time);
        String format = "%0" + PASSWORD_LENGTH + "d";
        return String.format(format, password);
    }

    public Optional<String> createTotp(String strKey){
        try {
            return Optional.of(createTotp(decodeStringToKey(strKey), Instant.now()));
        }catch (Exception e){
            e.printStackTrace();
            return Optional.empty();
        }
    }

    /**
     * 校验一次性验证码
     * @param code
     * @return
     * @throws InvalidKeyException
     */
    public boolean verifyTotp(String code) throws InvalidKeyException {
        return code.equals(createTotp(keyGenerator.generateKey(), Instant.now()));
    }

    public Key generateKey(){
        return keyGenerator.generateKey();
    }

    public String encodeKeyToString(Key key){
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public String encodeKeyToString(){
        return encodeKeyToString(generateKey());
    }

    public Key decodeStringToKey(String strKey){
        return new SecretKeySpec(Base64.getDecoder().decode(strKey), totp.getAlgorithm());
    }

    public long getTimeTemp() {
        return TIME_TEMP;
    }
}
