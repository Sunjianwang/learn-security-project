package learn.controller;

import learn.entity.User;
import learn.entity.dto.LoginDto;
import learn.entity.dto.UserDto;
import learn.service.UserService;
import learn.userdetail.LearnUserDetailsPassword;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.validation.Valid;

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
    private UserService userService;

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

    @PreAuthorize("authentication.name.equals(#loginDto.username)")
    @PostMapping("updatePassword")
    public void updatePassword(@Valid @RequestBody LoginDto loginDto){
        userService.updatePassword(loginDto);
    }

    @GetMapping("/users/{username}")
    public String getUserName(@PathVariable String username){
        return username;
    }
}
