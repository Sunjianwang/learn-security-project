package learn.controller;

import learn.entity.dto.UserDto;
import learn.userdetail.LearnUserDetailsPassword;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.validation.Valid;
import javax.websocket.server.PathParam;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RestController
@RequestMapping("user")
public class UserController {

    @Resource
    private LearnUserDetailsPassword userDetailsPassword;

    @GetMapping("hello")
    public String hello(){
        return "Hello Security";
    }

    @PostMapping("hello")
    public String helloName(@RequestParam String name){
        return "Hello Security: " + name;
    }

    @PostMapping("register")
    public UserDto register(@Valid @RequestBody UserDto userDto){
        return userDto;
    }

    @GetMapping("principal")
    public Authentication getPrincipal(Authentication authentication){
        return authentication;
    }

    @PostMapping("updatePassword")
    public void updatePassword(Authentication authentication,  @RequestParam String newPassword){
        userDetailsPassword.updatePassword((UserDetails) authentication.getPrincipal(), newPassword);
    }

    @GetMapping("/users/{username}")
    public String getUserName(@PathVariable String username){
        return username;
    }
}
