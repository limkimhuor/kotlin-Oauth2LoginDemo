//package com.hlk.web.config
//
//import org.springframework.context.annotation.Configuration
//import org.springframework.security.config.annotation.web.builders.HttpSecurity
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
//
//
//@Configuration
//class WebSecurityConfig: WebSecurityConfigurerAdapter() {
//    @Throws(Exception::class)
//    override fun configure(http: HttpSecurity?) {
//        http!!.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .oauth2Login()
//    }
//}
