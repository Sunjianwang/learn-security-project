package learn.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import learn.entity.Role;
import learn.entity.User;
import learn.entity.dto.LoginDto;
import learn.util.JwtUtil;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.HashSet;
import java.util.Set;

@SpringBootTest
class UserControllerTest {

    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext context;
    private User mockUserWithRoleUser;
    @Autowired
    private ObjectMapper objectMapper;

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

        mockUserWithRoleUser = User.builder()
                .username("user")
                .password("12345678")
                .roles(roleSets).build();
    }

    @WithMockUser(roles = {"USER", "ADMIN"})
    @Test
    void helloNameByMockUser() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/user/hello")
                        .param("name", "user"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("user")));
    }

    @WithMockUser(roles = {"USER"})
    @Test
    void getPrincipal() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/user/principal"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andDo(MockMvcResultHandlers.print());
    }

    @WithMockUser(password = "12345678")
    @Test
    void updatePassword() throws Exception {
        //相同用户名
        mockMvc.perform(MockMvcRequestBuilders.post("/user/updatePassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginDto("user", "12345678"))))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk());

        //修改非登录信息用户名
        mockMvc.perform(MockMvcRequestBuilders.post("/user/updatePassword")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginDto("user1", "12345678"))))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }
}