

package com.jwtauth.jwtauth.Repository ;

import java.util.Optional ;

import org.springframework.data.jpa.repository.JpaRepository ;

import com.jwtauth.jwtauth.Model.User ;

public interface jwtUserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUsername(String username);

}
