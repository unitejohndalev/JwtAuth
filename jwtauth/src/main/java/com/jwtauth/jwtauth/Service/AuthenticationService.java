

package com.jwtauth.jwtauth.Service ;

import org.springframework.security.authentication.AuthenticationManager ;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken ;
import org.springframework.security.crypto.password.PasswordEncoder ;
import org.springframework.stereotype.Service ;

import com.jwtauth.jwtauth.Model.AuthenticationRequest ;
import com.jwtauth.jwtauth.Model.AuthenticationResponse ;
import com.jwtauth.jwtauth.Model.RegisterRequest ;
import com.jwtauth.jwtauth.Model.Role ;
import com.jwtauth.jwtauth.Model.User ;
import com.jwtauth.jwtauth.Repository.jwtUserRepository ;

import lombok.RequiredArgsConstructor ;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final jwtUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register( RegisterRequest request ) {
    var user = User.builder()
    .username(request.getUsername())
    .firstname(request.getFirstname())
    .lastname(request.getLastname())
    .email(request.getEmail())
    .password(passwordEncoder.encode(request.getPassword()))
    .role(Role.USER)
    .build();
    repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
    .token(jwtToken)
    .build();
        
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request ) {
    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
        request.getUsername(),
        request.getPassword()

    ));
    var user  = repository.findByUsername(request.getUsername())
    .orElseThrow();
    var jwtToken = jwtService.generateToken( user ) ;
    return AuthenticationResponse.builder().token( jwtToken ).build() ;
    }


}
