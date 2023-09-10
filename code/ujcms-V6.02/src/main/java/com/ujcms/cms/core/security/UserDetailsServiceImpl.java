package com.ujcms.cms.core.security;

import com.ujcms.cms.core.domain.User;
import com.ujcms.cms.core.service.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Spring Security UserDetailsService 的实现类
 *
 * @author PONY
 */
public class UserDetailsServiceImpl implements UserDetailsService, UserDetailsPasswordService {
    private final UserService userService;

    public UserDetailsServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.selectByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("username not found: " + username);
        }
        return user;
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        if (user instanceof User) {
            User u = (User) user;
            userService.updatePassword(u, u.getExt(), newPassword);
            return user;
        }
        throw new IllegalArgumentException("user not instanceof User:" + user);
    }
}
