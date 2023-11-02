package demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RestController
@RequestMapping("user")
public class UserController {

    @GetMapping("info")
    public Authentication hello(Authentication authentication){
        return authentication;
    }
}
