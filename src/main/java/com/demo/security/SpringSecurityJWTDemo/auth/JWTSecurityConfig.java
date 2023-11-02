package com.demo.security.SpringSecurityJWTDemo.auth;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/* 
 * 1. Create KeyPair
 * 2. Create RSAKey Object using that KeyPair
 * 3. Create JWKSource using RSAKey Object to use our KeyPair
 * 4. Use RSAPublic Key for Decoding
 * 5. Create a JWTEncoder
 * */


@Configuration
public class JWTSecurityConfig {

	@Bean
	SecurityFilterChain customFilter(HttpSecurity http,  HandlerMappingIntrospector introspector) throws Exception
	{
		http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());  // All Request Should be Authenticated
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // Set Session to Stateless
        http.httpBasic(Customizer.withDefaults()); // Enable Basic Authentication
        http.csrf(csrf -> csrf.disable()); // Disable CSRF
        http.headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin())); // Allow Frames from sameorigin
        http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		
		return http.build();
	}
	
	
	// DB Authentication Process
	@Bean
	UserDetailsService userDetailService(DataSource datasource)
	{
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(datasource);
		
		UserDetails user1 = User.withUsername("john")
		.password("dummy")
		.passwordEncoder(str -> passwordEncoder().encode(str))
		.roles("USER")
		.build();
		
		UserDetails user2 = User.withUsername("admin")
		.password("admin")
		.passwordEncoder(str -> passwordEncoder().encode(str))
		.roles("USER", "ADMIN")
		.build();
		
		jdbcUserDetailsManager.createUser(user1);
		jdbcUserDetailsManager.createUser(user2);
		
		return jdbcUserDetailsManager;
	}

	// Configure Datasource
    @Bean
    DataSource datasource()
	{
       return new EmbeddedDatabaseBuilder()
        .setType(EmbeddedDatabaseType.H2)
        .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // Script to create user & authorities tables in the database
        .build();
	}
    
    // Defining Password Encoder
    @Bean
    BCryptPasswordEncoder passwordEncoder()
    {
    	return new BCryptPasswordEncoder();
    }
    
    // Defining a Asymmetric keypair for encryption & decryption of JWT
    @Bean
    KeyPair keyPair()
    {
    	KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
	    	keyGen.initialize(2048);
	    	return keyGen.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
    }
    
    @Bean
    RSAKey rsaKey(KeyPair keyPair) {
    	 return new RSAKey
    			 .Builder((RSAPublicKey) keyPair.getPublic())
    	 		.privateKey(keyPair.getPrivate())
    	 		.keyID(UUID.randomUUID().toString())
    	 		.build();
    }
    
    // Defining JWKSource using our keyPair
    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey rsaKey)
    {
    	JWKSet jwkSet = new JWKSet(rsaKey);
    	
//    	return new JWKSource() {
//
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				// TODO Auto-generated method stub
//				return jwkSelector.select(jwkSet);
//			}};
    	
    	return (jwkSelector, context)-> jwkSelector.select(jwkSet);
    }
    
    // Defining JWT Decoder 
    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException
    {
    	return NimbusJwtDecoder
    			.withPublicKey(rsaKey.toRSAPublicKey())
    			.build();
    }
    
    // Defining JWT Encoder
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource)
    {
    	return new NimbusJwtEncoder(jwkSource);
    }
}
