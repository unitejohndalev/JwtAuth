

package com.jwtauth.jwtauth.Config ;

import java.util.Arrays ;

import org.springframework.context.annotation.Bean ;
import org.springframework.context.annotation.Configuration ;
import org.springframework.security.authentication.AuthenticationProvider ;
import org.springframework.security.config.annotation.web.builders.HttpSecurity ;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity ;
import org.springframework.security.config.http.SessionCreationPolicy ;
import org.springframework.security.web.SecurityFilterChain ;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter ;
import org.springframework.web.cors.CorsConfiguration ;

import com.jwtauth.jwtauth.Filter.JwtAuthenticationFilter ;

import lombok.RequiredArgsConstructor ;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter ;
    private final AuthenticationProvider authenticationProvider ;

    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)  throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration configuration = new CorsConfiguration();
                    configuration.setAllowedOrigins(Arrays.asList("*")); // Set allowed origins
                    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Set allowed methods
                    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept")); // Set allowed headers
                    return configuration;
                }))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/api/v1/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

}
