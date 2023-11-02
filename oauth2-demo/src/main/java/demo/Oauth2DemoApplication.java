package demo;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@MapperScan("demo")
@SpringBootApplication
public class Oauth2DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(Oauth2DemoApplication.class, args);
    }
}
