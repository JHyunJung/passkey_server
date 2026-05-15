package com.crosscert.passkey;

import com.crosscert.passkey.credential.metadata.MdsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(MdsProperties.class)
public class PasskeyApplication {

  public static void main(String[] args) {
    SpringApplication.run(PasskeyApplication.class, args);
  }
}
