package com.crosscert.passkey;

import com.crosscert.passkey.auth.apikey.service.ApiKeyProperties;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.metadata.MdsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({
  MdsProperties.class,
  ApiKeyProperties.class,
  WebauthnCeremonyProperties.class
})
public class PasskeyApplication {

  public static void main(String[] args) {
    SpringApplication.run(PasskeyApplication.class, args);
  }
}
