package com.api.dentist;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;

import static com.api.dentist.constant.FileConstant.USER_FOLDER;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan
public class DentistApplication {

	public static void main(String[] args) {
		SpringApplication.run(DentistApplication.class, args);
		new File(USER_FOLDER).mkdirs();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
