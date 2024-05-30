

package com.jwtauth.jwtauth.Filter ;


import java.io.IOException ;

import org.springframework.lang.NonNull ;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken ;
import org.springframework.security.core.context.SecurityContextHolder ;
import org.springframework.security.core.userdetails.UserDetails ;
import org.springframework.security.core.userdetails.UserDetailsService ;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource ;
import org.springframework.stereotype.Component ;
import org.springframework.web.filter.OncePerRequestFilter ;

import com.jwtauth.jwtauth.Service.JwtService ;

import jakarta.servlet.FilterChain ;
import jakarta.servlet.ServletException ;
import jakarta.servlet.http.HttpServletRequest ;
import jakarta.servlet.http.HttpServletResponse ;
import lombok.RequiredArgsConstructor ;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService ;
    private final UserDetailsService userDetailsService ;

    @Override
    protected void doFilterInternal(
        @NonNull
        HttpServletRequest request,
        @NonNull
        HttpServletResponse response,
        @NonNull
        FilterChain filterChain ) throws ServletException, IOException {


        final String authHeader = request.getHeader("Authorization"); // Retrieving the Authorization header from the request
        final String jwt;
        final String userName;
        if(authHeader == null || !authHeader.startsWith("Bearer ")) { // Checking if the Authorization header is null or does not start with "Bearer "
            filterChain.doFilter(request, response); // Passing the request and response to the next filter in the chain
            return;
        }
        jwt = authHeader.substring(7); // Extracting the JWT token from the Authorization header
        userName = jwtService.extractUsername(jwt);
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername( userName);
            if(jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response); // Passing the request and response to the next filter in the chain
    }
}
