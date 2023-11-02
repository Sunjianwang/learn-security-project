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
@RequestMapping("admin")
public class AdminController {

    @GetMapping("hello")
    public String hello(Authentication authentication){
        return "Hello Admin：" + authentication.getName();
    }
}
