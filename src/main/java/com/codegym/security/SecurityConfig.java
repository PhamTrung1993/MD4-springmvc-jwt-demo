package com.codegym.security;

import com.codegym.rest.CustomAccessDeniedHandler;
import com.codegym.rest.JwtAuthenticationTokenFilter;
import com.codegym.rest.RestAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@ComponentScan("com.codegym")
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //Thay vì validate bằng form login, ta sử dụng bean jwtAuthenticationTokenFilter để thực hiện filter request.
    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter() {
        return new JwtAuthenticationTokenFilter();
    }
    //Bean restServicesEntryPoint  sẽ xử lý những request chưa được xác thực.
    @Bean
    public RestAuthenticationEntryPoint restServicesEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }
    //Trường hợp người dùng gửi request mà không có quyền sẽ do bean customAccessDeniedHandlerxử lý
    // (Ví dụ chỉ có role USER nhưng gửi request xóa user)
    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("kai").password("{noop}12345").roles("ADMIN")
                .and()
                .withUser("sena").password("{noop}12345").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().ignoringAntMatchers("/**");
        http.httpBasic().authenticationEntryPoint(restServicesEntryPoint());
        http.authorizeRequests()
                //Với các url /rest/** sẽ chỉ cho phép người dùng đã đăng nhập.
                .antMatchers("/", "/rest/login").permitAll()
                //Các url /rest/** với method GET (API lấy thông tin user) cho phép cả role ADMIN và USER truy cập,
                // với các method “DELETE” và “POST” (xóa và tạo mới user) thì chỉ cho phép role ADMIN truy cập.
                .antMatchers(HttpMethod.GET,"/rest/**").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.POST,"/rest/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,"/rest/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and().csrf().disable();
        http.addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling().accessDeniedHandler(customAccessDeniedHandler());
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.cors();
    }
}
