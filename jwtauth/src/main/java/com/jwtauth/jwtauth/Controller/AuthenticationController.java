

package com.jwtauth.jwtauth.Controller ;

import org.springframework.http.ResponseEntity ;
import org.springframework.web.bind.annotation.PostMapping ;
import org.springframework.web.bind.annotation.RequestBody ;
import org.springframework.web.bind.annotation.RequestMapping ;
import org.springframework.web.bind.annotation.RestController ;

import com.jwtauth.jwtauth.Model.AuthenticationRequest ;
import com.jwtauth.jwtauth.Model.AuthenticationResponse ;
import com.jwtauth.jwtauth.Model.RegisterRequest ;
import com.jwtauth.jwtauth.Service.AuthenticationService ;

import lombok.RequiredArgsConstructor ;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register (
        @RequestBody RegisterRequest request
    )
    {
        return ResponseEntity.ok(service.register(request));
    }

    
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register (
        @RequestBody AuthenticationRequest request
    )
    {
        return ResponseEntity.ok(service.authenticate(request));
    }

}
