package learn.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import learn.config.AppProperties;
import learn.entity.Role;
import learn.entity.User;
import learn.entity.dto.LoginDto;
import learn.entity.dto.TotpVerificationDto;
import learn.entity.dto.UserDto;
import learn.util.JwtUtil;
import learn.util.TotpUtil;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import static org.hamcrest.Matchers.*;

@SpringBootTest
class AuthControllerTest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    private LoginDto loginUser;

    private User mockUserWithRoleUser;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private TotpUtil totpUtil;

    @Autowired
    private ObjectMapper objectMapper;

    private final String keyStr = "OTNkNDllMTctNzQ4NS00ZDEzLWJiNWUtNmYzYWVhNjM4YzVm";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        Set<Role> roleSets = new HashSet<>();
        roleSets.add(Role.builder()
                .roleName("ROLE_USER")
                .permissions(new HashSet<>())
                .build()
        );

        loginUser = new LoginDto("user", "123456");

        mockUserWithRoleUser = User.builder()
                .username("user")
                .password("12345678")
                .roles(roleSets)
                .build();
    }

    /**
     * 二次登录验证
     * @throws Exception
     */
    @Test
    void totpLogin() throws Exception {
//        Mockito.doNothing().when(smsService).sendSms(keyStr);
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUser))
                        .locale(Locale.CHINA))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.header().exists("X-Authenticate"))
                .andExpect(MockMvcResultMatchers.header().stringValues("X-Authenticate", hasItems(is("mfa"), containsString("mfaId="))))
                .andReturn();
        Instant now = Instant.now();
        String code = totpUtil.createTotp(totpUtil.decodeStringToKey(keyStr), now);
        //错误验证码验证
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/verifyTotp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpVerificationDto(keyStr, "错误的验证码"))))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());

        //正确验证码验证
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/verifyTotp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpVerificationDto(keyStr, code))))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());

        //正确验证码重复验证
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/verifyTotp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpVerificationDto(keyStr, code))))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    /**
     * 测试刷新Token获取
     *
     * @return
     * @throws Exception
     */
    @Test
    void refreshToken() throws Exception {
        long pastTime = Instant.now().minusNanos(appProperties.getJwt().getAccessTokenExpireTime()).toEpochMilli();
        String refreshToken = jwtUtil.refreshToken(mockUserWithRoleUser);
        String accessToken = jwtUtil.accessToken(mockUserWithRoleUser, pastTime);
        mockMvc.perform(MockMvcRequestBuilders.get("/auth/refreshToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .param("refreshToken", refreshToken))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.jsonPath("accessToken", Matchers.is(Matchers.notNullValue())))
                .andExpect(MockMvcResultMatchers.jsonPath("refreshToken", Matchers.is(Matchers.notNullValue())))
                .andExpect(MockMvcResultMatchers.jsonPath("accessToken", Matchers.not(accessToken)))
                .andExpect(MockMvcResultMatchers.jsonPath("refreshToken", Matchers.is(refreshToken)));
    }

    /**
     * 测试Token获取
     * 请求参数为账号密码，成功返回Token，失败返回401
     */
    @Test
    void token() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .locale(Locale.CHINA)
                        .header("Authorization", "Basic c3lzdGVtLXVzZXI6c2VjcmV0")
                        .queryParam("grant_type", "password")
                        .queryParam("username", "user")
                        .queryParam("password", "1234568")
                        .queryParam("scope", "USER"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());

    }
}