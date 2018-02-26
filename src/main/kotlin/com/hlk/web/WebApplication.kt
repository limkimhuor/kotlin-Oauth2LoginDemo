package com.hlk.web

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal
import org.springframework.security.oauth2.client.OAuth2ClientContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import javax.servlet.Filter
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter
import org.springframework.web.filter.CompositeFilter


@SpringBootApplication
@EnableOAuth2Client
@RestController
class WebApplication: WebSecurityConfigurerAdapter() {
    @RequestMapping("/user")
    fun user(principal: Principal): Principal {
        return principal
    }

    @Autowired
    val oauth2ClientContext: OAuth2ClientContext? = null

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
            .antMatcher("/**")
            .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**")
                .permitAll()
            .anyRequest()
                .authenticated()
            .and().logout().logoutSuccessUrl("/").permitAll()
            .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter::class.java)
    }

    private fun ssoFilter(): Filter {
        val filter = CompositeFilter()
        val filters: MutableList<Filter> = arrayListOf()
        filters.add(ssoFilter(facebook(), "/login/facebook"))
        filters.add(ssoFilter(github(), "/login/github"))
        filter.setFilters(filters);
        return filter
    }

    private fun ssoFilter(client: ClientResources, path: String): Filter {
        val filter = OAuth2ClientAuthenticationProcessingFilter(path)
        val template = OAuth2RestTemplate(client.getClient(), oauth2ClientContext)
        filter.setRestTemplate(template)
        val tokenServices = UserInfoTokenServices(client.getResource().userInfoUri, client.getClient().clientId)
        tokenServices.setRestTemplate(template)
        filter.setTokenServices(tokenServices)
        return filter
    }

    class ClientResources {
      @NestedConfigurationProperty
      private val client = AuthorizationCodeResourceDetails()

      @NestedConfigurationProperty
      private val resource = ResourceServerProperties()

      fun getClient(): AuthorizationCodeResourceDetails {
        return client
      }

      fun getResource(): ResourceServerProperties {
        return resource
      }
    }

    @Bean
    @ConfigurationProperties("facebook")
    fun facebook(): ClientResources {
        return ClientResources()
    }

    @Bean
    @ConfigurationProperties("github")
    fun github(): ClientResources {
        return ClientResources()
    }

    @Bean
    fun oauth2ClientFilterRegistration(
            filter: OAuth2ClientContextFilter
    ): FilterRegistrationBean {
        val registration = FilterRegistrationBean()
        registration.filter = filter
        registration.order = -100
        return registration
    }
}

fun main(args: Array<String>) {
    SpringApplication.run(WebApplication::class.java, *args)
}
