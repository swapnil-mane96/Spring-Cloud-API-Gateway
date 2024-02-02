package com.photoapp.apigateway;

import java.util.Base64;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;


@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
	
	@Autowired
	private Environment environment;
	
	/*
	 * It will tell super class which Config class to use when apply method is called
	 *
	 */
	public AuthorizationHeaderFilter() {
		super(Config.class);
	}

	public static class Config{
		// put configuration properties here
	}

	/*
	 * This method contains main business logic of our custom filter leaves
	 * It accepts config object which we can use to access configuration properties 
	 * If needed customize behavior of our gateway filter 
	 * And apply method it will need to return an object of gateway filter
	 */
	@Override
	public GatewayFilter apply(Config config) {
		
		return (exchange, chain) ->{
			ServerHttpRequest serverHttpRequest = exchange.getRequest(); // Get request from Http server
			
			// Now we have serverHttpRequest object so we can check Http header with Authorization name 
			if (!serverHttpRequest.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
			}
			// Get entire jwt token including Bearer prefix and jwt token
			String authorizationHeader = serverHttpRequest.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			
			// It will remove Bearer prefix from jwt token and give jwt token only.
			String jwtBearer = authorizationHeader.replace("Bearer", "");
			
			String jwt = jwtBearer.trim();
			
			if (!isJwtValid(jwt)) {
				return onError(exchange, "Jwt token is not valid!", HttpStatus.UNAUTHORIZED);
			}
			return chain.filter(exchange);
		};
	}
	
	/*
	 * The method returns a Mono<Void> due to the asynchronous, non-blocking nature of Spring WebFlux,
	 *  which is used in Spring Cloud Gateway for handling HTTP requests and responses in a reactive way.
	 */
	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus){
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		return response.setComplete();
	}
	
	private boolean isJwtValid(String jwt) {
		boolean returnValue = true;
		String subject = null;
		String tokenSecret = this.environment.getProperty("token.secret");
		System.out.println("API Gateway Secret Token: "+tokenSecret);
		byte[] secretBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
		SecretKey secretKey = Keys.hmacShaKeyFor(secretBytes);
		
		//To parse access token and to read it's claims we will need to use JWT parser
		JwtParser jwtParser = Jwts.parser()
				.verifyWith(secretKey)
				.build();

		try {
			Claims claims = jwtParser.parseSignedClaims(jwt).getPayload();
			subject = claims.getSubject();
			System.out.println("Subject is: "+subject);
			
		} catch (Exception exception) {
			exception.printStackTrace();
			System.out.println("API Gateway Exception is: "+exception.getMessage());
			returnValue = false;
		}
		
		if (subject == null || subject.isEmpty() ) {
			returnValue = false;
		}
		
		return returnValue;
	}
	

}
