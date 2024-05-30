

package com.jwtauth.jwtauth.Config ;

import org.springframework.context.annotation.Configuration ;
import org.springframework.web.servlet.config.annotation.CorsRegistry ;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer ;


@Configuration
public class WebConfig implements WebMvcConfigurer {

    // Configuration class for web-related settings

    @SuppressWarnings( "null" )
    @Override
    public void addCorsMappings(
        CorsRegistry registry ) {
        // Configures Cross-Origin Resource Sharing (CORS)
        // mappings

        // Allows requests from http://localhost:3000
        registry
            .addMapping( "/**" )
            .allowedOrigins( "http://localhost:3000" )
            // Allows all HTTP methods
            .allowedMethods( "*" )
            // Allows all headers
            .allowedHeaders( "*" )
            // Exposes the Authorization header to the
            // client
            .exposedHeaders( "Authorization" )
            // Allows credentials (e.g., cookies,
            // authorization headers) to be sent with
            // cross-origin requests
            .allowCredentials( true ) ;
    }
}
