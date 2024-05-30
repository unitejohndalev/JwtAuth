

package com.jwtauth.jwtauth.Service ;


import org.springframework.security.core.userdetails.UserDetails ;
import org.springframework.stereotype.Service ;
import java.security.Key ;
import java.util.Date ;
import java.util.HashMap ;
import java.util.Map ;
import java.util.function.Function ;

import io.jsonwebtoken.Claims ;
import io.jsonwebtoken.Jwts ;
import io.jsonwebtoken.SignatureAlgorithm ;
import io.jsonwebtoken.io.Decoders ;
import io.jsonwebtoken.security.Keys ;



@Service
public class JwtService {

    private static final String SECRET_KEY = "A8109E356C606EB46863B1984942F4C4E641CE2D7416855646AEB7860669FC76233ED9FE3C93A25C3874996E6CE6B093407B9E160BD1CF6BF1254983D44969282ADE73535248D19196278AEA5B2C3B070C6802BAF93A3AAFA49CE5D83B1809138A23BF90BA1E28BD9873608AEBAAEE9CDC767BF11C3DDFC5049F14A6227C1B29";

    public String extractUsername(String token ) {
    return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token,Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //this method will generate only using userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken( Map<String, Object> extractClaims, UserDetails userDetails) {
       return Jwts
       .builder()
       .setClaims(extractClaims)
       .setSubject(userDetails.getUsername())
       .setIssuedAt(new Date(System.currentTimeMillis()))
       .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //when it expires
       .signWith(getSignInKey(), SignatureAlgorithm.HS256)
       .compact(); // this will generate and return the token
    }

    public boolean isTokenValid(String token, UserDetails userDetails) { 
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token); 
    }

    private boolean isTokenExpired(String token ) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token ) {
    return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
      
    }

}
