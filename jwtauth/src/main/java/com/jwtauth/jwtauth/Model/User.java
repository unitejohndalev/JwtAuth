

package com.jwtauth.jwtauth.Model ;


import java.util.Collection ;
import java.util.List ;

import org.springframework.security.core.GrantedAuthority ;
import org.springframework.security.core.authority.SimpleGrantedAuthority ;
import org.springframework.security.core.userdetails.UserDetails ;

import jakarta.persistence.Column ;
import jakarta.persistence.Entity ;
import jakarta.persistence.EnumType ;
import jakarta.persistence.Enumerated ;
import jakarta.persistence.GeneratedValue ;
import jakarta.persistence.Id ;
import jakarta.persistence.Table ;
import lombok.AllArgsConstructor ;
import lombok.Builder ;
import lombok.Data ;
import lombok.NoArgsConstructor ;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table( name = "jwt_user" )
public class User implements UserDetails {

    @Id
    @GeneratedValue

    @Column( name = "id" )
    private Integer id ;

    @Column( name = "username" )
    private String username ;

    @Column( name = "firstname" )
    private String firstname ;

    @Column( name = "lastname" )
    private String lastname ;

    @Column( name = "email" )
    private String email ;

    @Column( name = "password" )
    private String password ;

    @Enumerated( EnumType.STRING )
    private Role role ;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return List.of( new SimpleGrantedAuthority( role.name() ) ) ;
    }


    @Override
    public String getUsername() {

        return username ;
    }


    @Override
    public boolean isAccountNonExpired() {

        return true ;
    }


    @Override
    public boolean isAccountNonLocked() {

        return true ;
    }


    @Override
    public boolean isCredentialsNonExpired() {

        return true ;
    }


    @Override
    public boolean isEnabled() {

        return true ;
    }
}
