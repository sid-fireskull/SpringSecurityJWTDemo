package com.demo.security.SpringSecurityJWTDemo.auth;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class JWTAuthenticationController {
	
	JwtEncoder jwtEncoder;
	
	public JWTAuthenticationController(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<JwtTokenResponse> generateToken(Authentication auth)
	{
		JwtTokenResponse res = new  JwtTokenResponse(createToken(auth));
		return ResponseEntity.ok(res);
	}
	
	// Create JWT Token From Claims
	private String createToken(Authentication auth) {
		JwtClaimsSet claims = JwtClaimsSet
								.builder()
								.issuer("self")
								.issuedAt(Instant.now())
								.expiresAt(Instant.now().plusSeconds(60*60))
								.subject(auth.getName())
								.claim("scope", createScope(auth))
								.build();
		
		return jwtEncoder
				.encode(JwtEncoderParameters.from(claims))
				.getTokenValue();
	}

	private String createScope(Authentication auth) {
		return auth
				.getAuthorities()
				.stream()
				.map(a -> a.getAuthority())
				.collect(Collectors.joining(" "));
	}
}
