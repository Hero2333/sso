package cn.iocoder.yudao.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"cn.iocoder.yudao.sso", "cn.iocoder.yudao.module"})
public class SSODemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SSODemoApplication.class, args);
    }

}
