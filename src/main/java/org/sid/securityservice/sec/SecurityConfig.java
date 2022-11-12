package org.sid.securityservice.sec;

import org.sid.securityservice.sec.filters.JwtAuthenticationFilter;
import org.sid.securityservice.sec.filters.JwtAuthorizationFilter;
import org.sid.securityservice.sec.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends  WebSecurityConfigurerAdapter {

    private UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //Avec cette ligne on disactive le csrf,   en plus de ça il faut le désactiver car nous allons utiliser JWT,
        // si on le laisse   csrf utiliser les sessions et cookie donc ce n'est pas ce qu'on veut
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();

        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**", "/login/**").permitAll();
        //http.formLogin();

        // On va jute dire que quand il sagit d'une methode POST  il faut un role admin et pour  GET un role user
        // http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAnyAuthority("ADMIN");
        // http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAnyAuthority("USER");

        http.authorizeRequests().anyRequest().authenticated();
        // il faut ajouter Le filter
        // la classe JwtAuthenticationFilter prend en paramètre un objet authenticationManager c'est pour ce la nous
        // avons redifini la méthode authenticationManagerBean() en bàs
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        // ajouter le filter comme befor  pour que ça soit exécuté en premier
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

    }



    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
