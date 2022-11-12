package org.sid.securityservice.sec.service;

import org.sid.securityservice.sec.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private AccountService accountService;

    public UserDetailsServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.loadUserByUsername(username);

        Collection<GrantedAuthority> grantedAuthorities =
                appUser.getAppRoles()
                        .stream()
                        .map( role -> new SimpleGrantedAuthority(role.getRoleName()))
                        .collect(Collectors.toList());
        User user = new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
        return  user;
    }
}
